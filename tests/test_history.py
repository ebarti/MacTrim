import copy
import gzip
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from mactrim.config import defaults
from mactrim.history import History, MAX_BYTES, MAX_DECODED, MAX_ENTRIES, compare
from mactrim.measurement import measure
from mactrim.safety import SafetyError
from mactrim.state import State

CAPACITY = [{'path': '/', 'label': 'System filesystem', 'status': 'measured', 'total': 1000000, 'used': 400000, 'available': 600000},
            {'path': '/System/Volumes/Data', 'label': 'APFS Data filesystem', 'status': 'measured', 'total': 1000000, 'used': 400000, 'available': 600000}]


class HistoryTests(unittest.TestCase):
    def setUp(self):
        parent = Path.cwd() / 'evidence'
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.root = Path(self.temporary.name)
        self.data = self.root / 'data'
        self.data.mkdir()
        self.state = State(self.root / 'state').prepare()
        self.config = defaults()
        self.config['storage_max_files'] = 1000
        self.history = History(self.state, self.config)

    def tearDown(self):
        self.temporary.cleanup()

    def capture(self, now=None, automatic=False):
        node = measure(self.data, 1000, 16, storage=True)
        return self.history.capture(node, CAPACITY, now=now, automatic=automatic)

    def bodies(self):
        return [row['body'] for row in self.history.inventory()[0]]

    def test_two_actual_walks_growth_shrink_new_and_stable_repeat(self):
        for name, size in (('expand', 20), ('removed', 30), ('stable', 40)):
            path = self.data / name
            path.mkdir()
            (path / 'file.txt').write_bytes(b'x' * size)
        now = time.time() - 10
        first = self.capture(now)
        (self.data / 'expand' / 'file.txt').write_bytes(b'x' * 70)
        (self.data / 'removed' / 'file.txt').unlink()
        (self.data / 'removed').rmdir()
        (self.data / 'new').mkdir()
        (self.data / 'new' / 'file.txt').write_bytes(b'x' * 90)
        second = self.capture(now + 1)
        result = self.history.compare(first['id'], second['id'], 'logical')
        rows = {Path(row['path']).name: row for row in result['rows']}
        self.assertEqual(rows['expand']['delta'], 50)
        self.assertEqual(rows['removed']['delta'], -30)
        self.assertEqual(rows['removed']['status'], 'removed-directory')
        self.assertIsNone(rows['removed']['after'])
        self.assertEqual(rows['new']['delta'], 90)
        self.assertEqual(rows['new']['status'], 'new-directory')
        self.assertIsNone(rows['new']['before'])
        self.assertTrue(rows['expand']['overlaps_parent'])
        third = self.capture(now + 2)
        repeated = self.history.compare(second['id'], third['id'], 'logical')
        self.assertTrue(all(row['delta'] == 0 for row in repeated['rows']))
        self.assertTrue(result['capacity'][1]['shared_observation_alias'])
        self.assertEqual(result['capacity'][0]['used_delta'], 0)

    def test_partial_missing_replaced_and_incompatible_are_unknown(self):
        child = self.data / 'child'
        child.mkdir()
        (child / 'a.txt').write_text('content')
        self.capture()
        first = self.bodies()[0]
        second = copy.deepcopy(first)
        second['id'] = 'f' * 32
        second['created_at'] += 1
        second['directories'][0]['status'] = 'partial'
        second['directories'][0]['children_complete'] = False
        second['directories'].append(dict(second['directories'][1], path=str(self.data / 'unmeasured-new')))
        result = compare(first, second, 'logical')
        root = next(row for row in result['rows'] if row['path'] == str(self.data))
        self.assertIsNone(root['delta'])
        # Missing prior aggregate cannot prove absence if complete directory
        # coverage was not retained (e.g. aggregate cap excludes a child).
        first['directories'][0]['children_complete'] = False
        result = compare(first, second, 'logical')
        new = next(row for row in result['rows'] if row['path'].endswith('unmeasured-new'))
        self.assertEqual(new['status'], 'newly-observed')
        self.assertIsNone(new['delta'])
        second['policy']['max_files'] += 1
        incompatible = compare(first, second)
        self.assertEqual(incompatible['rows'], [])
        self.assertTrue(incompatible['issues'])

    def test_aggregate_limit_does_not_limit_measurement_and_old_policy_stays_readable(self):
        for index in range(MAX_ENTRIES + 10):
            (self.data / str(index)).mkdir()
        node = measure(self.data, MAX_ENTRIES + 20, 16, storage=True)
        self.assertEqual(node.status, 'measured')
        self.assertEqual(node.entries, MAX_ENTRIES + 11)
        self.config['storage_max_files'] = MAX_ENTRIES + 20
        self.history.capture(node, CAPACITY)
        body = self.bodies()[0]
        self.assertLessEqual(len(body['directories']), MAX_ENTRIES)
        self.assertFalse(next(row for row in body['directories'] if row['path'] == str(self.data))['children_complete'])
        old = copy.deepcopy(body)
        old['policy']['collector'] = 'metadata.v2'
        self.history.validate(old, old['id'])
        self.assertTrue(compare(old, body)['issues'])
        self.assertEqual(compare(old, body)['rows'], [])

    def test_directory_only_caps_and_recent_clues_without_new_scan_or_hash(self):
        (self.data / 'child').mkdir()
        (self.data / 'child' / 'private-content.txt').write_bytes(b'x' * 1000)
        node = measure(self.data, 1000, 16, storage=True)
        with patch('mactrim.safety.file_hash', side_effect=AssertionError('history content hashing')):
            captured = self.history.capture(node, CAPACITY)
        body = self.bodies()[0]
        self.assertLessEqual(len(body['directories']), MAX_ENTRIES)
        self.assertFalse(any('private-content' in row['path'] for row in body['directories']))
        self.assertNotIn('records', json.dumps(body))
        self.assertNotIn('sha256', json.dumps(body))
        self.assertGreater(body['directories'][0]['recent']['modified_7d'], 0)
        self.assertLess(captured['encoded_bytes'], 10000)
        self.assertLessEqual(captured['allocated_bytes'], MAX_BYTES)

    def test_hard_allocated_count_age_retention_and_automatic_rate_limit(self):
        (self.data / 'a.txt').write_text('small content')
        self.config['history'].update(max_bytes=128 * 1024, max_snapshots=3, max_days=2)
        self.history = History(self.state, self.config)
        now = time.time() - 40
        self.capture(now - 3 * 86400)
        for index in range(30):
            result = self.capture(now + index)
            listing = self.history.list()
            self.assertLessEqual(listing['allocated_bytes'], 128 * 1024)
            self.assertLessEqual(len(listing['snapshots']), 3)
            self.assertFalse(any(row['temporary'] for row in listing['snapshots']))
        self.assertEqual(len(self.history.list()['snapshots']), 3)
        skipped = self.capture(now + 31, automatic=True)
        self.assertEqual(skipped['skipped'], 'automatic capture rate limit')
        self.assertEqual(self.history.clear()['removed'], 3)
        self.assertEqual(self.history.list()['snapshots'], [])

    def test_interrupted_valid_write_recovers_without_deleting_unknown_data(self):
        (self.data / 'a.txt').write_text('small content')
        self.capture(time.time() - 3)
        with patch('mactrim.history.rename_exclusive', side_effect=SystemExit('durable temp before commit')):
            with self.assertRaises(SystemExit):
                self.capture(time.time() - 2)
        self.assertTrue(any(row['temporary'] for row in self.history.list()['snapshots']))
        self.capture(time.time() - 1)
        self.assertEqual(len(self.history.list()['snapshots']), 3)
        self.assertFalse(any(row['temporary'] for row in self.history.list()['snapshots']))
        unknown = self.history.path / 'unique-unrecognized.txt'
        unknown.write_text('never prune this data')
        with self.assertRaisesRegex(SafetyError, 'Unexpected history'):
            self.capture()
        with self.assertRaises(SafetyError):
            self.history.clear()
        self.assertEqual(unknown.read_text(), 'never prune this data')
        self.assertEqual(len(self.history.list()['snapshots']), 3)

    def test_altered_symlink_and_oversized_compressed_records_are_retained_and_refused(self):
        (self.data / 'a.txt').write_text('small content')
        first = self.capture()
        filename = self.history.path / (first['id'] + '.json.gz')
        original = filename.read_bytes()
        envelope = json.loads(gzip.decompress(original))
        envelope['body']['directories'][0]['allocated'] += 1
        filename.write_bytes(gzip.compress(json.dumps(envelope).encode()))
        self.assertTrue(self.history.list()['issues'])
        with self.assertRaises(SafetyError):
            self.history.compare(first['id'])
        filename.write_bytes(original)
        target = self.root / 'unique.txt'
        target.write_text('preserve linked target')
        link = self.history.path / ('f' * 32 + '.json.gz')
        link.symlink_to(target)
        with self.assertRaises(SafetyError):
            self.capture()
        self.assertEqual(target.read_text(), 'preserve linked target')
        link.unlink()  # owned fixture link only
        bomb = self.history.path / ('f' * 32 + '.json.gz')
        bomb.write_bytes(gzip.compress(b'x' * (MAX_DECODED + 1)))
        bomb.chmod(0o600)
        with self.assertRaisesRegex(SafetyError, 'Decompressed'):
            self.capture()
        self.assertTrue(bomb.exists())

    def test_first_baseline_is_not_retroactive_growth_and_disable_does_not_capture(self):
        self.capture()
        result = self.history.compare()
        self.assertEqual(result['rows'], [])
        self.assertIn('another comparable observation is needed', result['note'])
        self.assertNotIn('380', result['note'])
        self.config['history']['enabled'] = False
        self.assertEqual(self.capture()['skipped'], 'history disabled')
        self.assertEqual(len(self.history.list()['snapshots']), 1)

    def test_retention_isolates_then_checks_raced_in_replacement_and_preserves_it(self):
        self.config['history']['max_snapshots'] = 1
        self.history = History(self.state, self.config)
        first = self.capture(time.time() - 2)
        target = self.history.path / (first['id'] + '.json.gz')
        replacement = self.root / 'unique-replacement'
        replacement.write_bytes(b'unapproved private content')
        replacement.chmod(0o600)
        from mactrim.history import rename_exclusive
        injected = []
        def replace_before_isolation(source_fd, source_name, target_fd, target_name):
            if source_name == target.name and '.retiring.' in target_name and not injected:
                os.replace(replacement, target)
                injected.append(True)
            return rename_exclusive(source_fd, source_name, target_fd, target_name)
        with patch('mactrim.history.rename_exclusive', side_effect=replace_before_isolation):
            with self.assertRaises(SafetyError):
                self.capture()
        self.assertTrue(injected)
        self.assertEqual(target.read_bytes(), b'unapproved private content')
        self.assertTrue(self.history.list()['issues'])

    def test_regular_hardlink_alias_is_never_a_directory_aggregate(self):
        (self.data / 'a').mkdir()
        (self.data / 'c').mkdir()
        original = self.data / 'a' / 'data.txt'
        original.write_text('hardlinked file metadata')
        alias = self.data / 'c' / 'hardlink.txt'
        os.link(original, alias)
        node = measure(self.data, 1000, 16, storage=True)
        alias_node = next(child for child in next(child for child in node.children if child.name == 'c').children if child.name == 'hardlink.txt')
        self.assertEqual(alias_node.kind, 'file')
        self.history.capture(node, CAPACITY)
        self.assertFalse(any(row['path'] == str(alias) for row in self.bodies()[0]['directories']))
