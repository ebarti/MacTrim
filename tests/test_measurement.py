import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from mactrim.measurement import capacities, measure


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        parent = Path.cwd() / 'evidence'
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_metadata_never_hashes_and_accounts_hardlinks_once(self):
        first = self.root / 'a'
        first.write_bytes(b'x' * 111)
        os.link(first, self.root / 'b')
        (self.root / 'link').symlink_to(first)
        with patch('mactrim.safety.file_hash', side_effect=AssertionError('must not hash')):
            node = measure(self.root)
        self.assertEqual(node.logical, 111)
        self.assertEqual(node.status, 'partial')
        self.assertEqual(node.children[1].alias_of, str(first))
        self.assertEqual(node.children[2].kind, 'symlink')

    def test_partial_denied_cancelled_are_not_zero_claims(self):
        for index in range(5):
            (self.root / str(index)).write_bytes(b'x' * 100)
        limited = measure(self.root, max_entries=2)
        self.assertEqual(limited.status, 'partial')
        self.assertEqual(limited.logical, 100)
        denied = self.root / 'denied'
        denied.mkdir()
        denied.chmod(0)
        try:
            self.assertEqual(measure(denied).status, 'denied')
        finally:
            denied.chmod(0o700)
        cancel = threading.Event()
        cancel.set()
        self.assertEqual(measure(self.root, cancel=cancel).status, 'cancelled')

    def test_data_alias_and_virtual_skip_even_same_device(self):
        with patch('mactrim.measurement.os.lstat', return_value=os.stat(self.root)), patch('mactrim.measurement.ancestor_identity'), patch('mactrim.measurement.directory_fd') as fd:
            fd.return_value.__enter__.return_value = os.open(self.root, os.O_RDONLY)
            with patch('mactrim.measurement.os.stat', return_value=os.stat(self.root)):
                node = measure('/System/Volumes/Data', storage=True)
                self.assertEqual(node.status, 'skipped')
                self.assertIn('/Users', node.alias_of)
                virtual = measure('/dev', storage=True)
                self.assertEqual(virtual.status, 'skipped')
            os.close(fd.return_value.__enter__.return_value)

    def test_capacity_root_exposes_data_separately(self):
        with patch('mactrim.measurement.Path.exists', return_value=True):
            items = capacities('/')
        self.assertEqual([item['path'] for item in items], ['/', '/System/Volumes/Data'])
        self.assertTrue(all('status' in item for item in items))
