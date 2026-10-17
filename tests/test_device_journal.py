import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mactrim import events
from mactrim.events import EventCollector, NativeEvents


class DeviceJournalTests(unittest.TestCase):
    def test_mount_change_invalidates_namespace_without_becoming_a_drop(self):
        reader = EventCollector('/fixture')
        reader._record(['/fixture/a/mount'], [64 | 128], [41])
        reader._process_pending()
        self.assertFalse(reader.issues)
        self.assertEqual(reader.diagnostics['drop_signals'], 0)
        self.assertEqual(reader.diagnostics['mount_signals'], 1)
        self.assertEqual(reader.paths, {'/fixture/a/mount', '/fixture/a'})

    def test_device_relative_paths_map_back_to_selected_namespace(self):
        reader = EventCollector('/Volumes/Example/project')
        reader.device_mount = '/Volumes/Example'
        reader._record(['project/child/'], [0], [42])
        reader._process_pending()
        self.assertEqual(reader.paths, {'/Volumes/Example/project/child'})
        self.assertFalse(reader.issues)

    def test_device_paths_cannot_escape_the_measured_scope(self):
        reader = EventCollector('/Volumes/Example/project')
        reader.device_mount = '/Volumes/Example'
        reader._record(['project/../../outside'], [0], [42])
        reader._process_pending()
        self.assertFalse(reader.paths)
        self.assertTrue(reader.issues)

    def test_coarsened_device_batch_keeps_watched_root_coordinates(self):
        reader = EventCollector('/Volumes/Example/project')
        reader.device_mount, reader.device_root = '/Volumes/Example', 'project'
        with patch.object(events, 'PENDING_BYTES', 1):
            reader._record(['project/child'], [0], [42])
        reader._process_pending()
        self.assertEqual(reader.paths, {'/Volumes/Example/project'})
        self.assertFalse(reader.issues)
        self.assertEqual(reader.diagnostics['coarsened_batches'], 1)

    def test_device_scope_binds_fixture_to_its_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            device, mount, relative = events.device_scope(root)
            self.assertEqual(device, root.stat().st_dev)
            self.assertEqual(Path(mount) / relative, root)
            self.assertEqual(os.stat(mount).st_dev, device)

    def test_split_readonly_system_watches_writable_data_in_visible_namespace(self):
        def observed(path):
            return SimpleNamespace(st_dev=2 if str(path) == '/System/Volumes/Data' else 1)
        with patch.object(Path, 'is_dir', return_value=True), \
             patch.object(events.os, 'lstat', side_effect=observed), \
             patch.object(events.os, 'statvfs', return_value=SimpleNamespace(f_flag=os.ST_RDONLY)):
            self.assertEqual(events.device_scope('/'), (2, '/', ''))

    def test_explicit_data_alias_keeps_its_selected_namespace(self):
        with patch.object(Path, 'is_dir', return_value=True), \
             patch.object(events.os, 'lstat', return_value=SimpleNamespace(st_dev=2)):
            self.assertEqual(events.device_scope('/System/Volumes/Data/Users/example'),
                             (2, '/System/Volumes/Data', 'Users/example'))

    def test_volume_root_mount_invalidates_selected_scope_not_unrelated_paths(self):
        reader = EventCollector('/Volumes/Example/project')
        reader.device_mount = '/Volumes/Example'
        reader._record([''], [64 | 128], [43])
        reader._process_pending()
        self.assertEqual(reader.paths, {'/Volumes/Example/project'})
        self.assertFalse(reader.issues)

    def test_actual_dropped_delivery_still_blocks_reuse(self):
        reader = EventCollector('/fixture')
        reader.device_mount = '/'
        reader._record(['fixture'], [3], [44])
        reader._process_pending()
        self.assertTrue(reader.issues)
        self.assertEqual(reader.diagnostics['drop_signals'], 1)

    @unittest.skipUnless(sys.platform == 'darwin', 'native macOS framework')
    def test_native_stream_uses_the_device_api_instead_of_host_history(self):
        import FSEvents as F
        import CoreFoundation as C
        reader = EventCollector('/fixture/project', 100)
        stream = object()
        with patch('mactrim.events.device_scope', return_value=(123, '/fixture', 'project')), \
             patch.object(F, 'FSEventStreamCreate', side_effect=AssertionError('host stream used')), \
             patch.object(F, 'FSEventStreamCreateRelativeToDevice', return_value=stream) as create, \
             patch.object(F, 'FSEventStreamScheduleWithRunLoop'), \
             patch.object(F, 'FSEventStreamStart', return_value=True), \
             patch.object(F, 'FSEventStreamStop'), patch.object(F, 'FSEventStreamInvalidate'), \
             patch.object(F, 'FSEventStreamRelease'), \
             patch.object(C, 'CFRunLoopRunInMode', side_effect=lambda *_: reader.stop.set()):
            reader._run()
        self.assertIsNone(reader.failure)
        self.assertEqual(create.call_args.args[3:6], (123, ['project'], 100))
        self.assertEqual(reader.device_mount, '/fixture')
        self.assertEqual(reader.diagnostics['source'], 'device-journal')

    @unittest.skipUnless(sys.platform == 'darwin', 'native macOS framework')
    def test_real_device_replay_detects_edit_and_keeps_valid_checkpoint(self):
        from mactrim.config import defaults
        from mactrim.incremental import inventory
        from mactrim.state import State
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            data = root / 'data'; data.mkdir()
            child = data / 'child'; child.mkdir()
            file = child / 'file'; file.write_bytes(b'initial')
            state = State(root / 'state').prepare()
            first = inventory(data, state, defaults(), full=True)
            self.assertTrue(first.refresh['cache']['reusable'])
            file.write_bytes(b'changed contents without touching the directory mtime')
            changed = inventory(data, state, defaults())
            self.assertEqual(changed.refresh['mode'], 'incremental')
            self.assertGreater(changed.logical, first.logical)
            self.assertEqual(changed.refresh['events']['source'], 'device-journal')
            self.assertEqual(changed.refresh['events']['drop_signals'], 0)
            self.assertTrue(changed.refresh['cache']['reusable'])


class JournalIndexContractTests(unittest.TestCase):
    def setUp(self):
        from mactrim.config import defaults
        from mactrim.state import State
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.data = self.root / 'data'; self.data.mkdir()
        (self.data / 'protected').mkdir()
        (self.data / 'protected' / 'file').write_bytes(b'payload')
        self.config = defaults()
        self.state = State(self.root / 'state').prepare()
        self.identity = patch('mactrim.incremental.volume_identity', return_value=[1, 2, 'fixture'])
        self.ids = patch('mactrim.events.current_id', return_value=100)
        self.identity.start(); self.ids.start()

    def tearDown(self):
        self.ids.stop(); self.identity.stop(); self.temporary.cleanup()

    def scan(self):
        from mactrim.incremental import inventory
        class QuietJournal:
            def __init__(self, *args): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def drain(self): return set(), [], 100
        return inventory(self.data, self.state, self.config, backend=QuietJournal)

    def test_old_host_index_requires_new_baseline_without_changing_history_policy(self):
        from mactrim.storage_cache import Cache, flatten
        first = self.scan()
        cache = Cache(self.state, self.config['storage_cache'])
        body = cache.read(details=False)[0]
        self.assertEqual(body['policy']['event_source'], 'device-journal.v1')
        self.assertNotIn('event_source', first.policy)
        # A previous host-journal index can look otherwise compatible. Its
        # checkpoint must never authorize reuse under the new journal source.
        body['policy'].pop('event_source')
        body['directories'] = flatten(first)
        cache.write(body)
        baseline = self.scan()
        self.assertEqual(baseline.refresh['mode'], 'full')
        self.assertEqual(baseline.counters['reused'], 0)
        self.assertEqual(baseline.policy, first.policy)
        self.assertTrue(baseline.refresh['cache']['reusable'])
        self.assertEqual(self.scan().refresh['mode'], 'incremental')

    def test_permission_partial_observation_is_saved_and_can_reuse_accessible_subtrees(self):
        original = os.open
        def open_directory(path, *args, **kwargs):
            if str(path) == 'protected':
                raise PermissionError(13, 'Permission denied', str(path))
            return original(path, *args, **kwargs)
        with patch('mactrim.storage.os.open', side_effect=open_directory):
            observed = self.scan()
        self.assertEqual(observed.status, 'partial')
        self.assertTrue(observed.refresh['cache']['stored'])
        self.assertTrue(observed.refresh['cache']['reusable'])
        self.assertGreater(observed.refresh['coverage']['counts']['permissions'], 0)
        self.assertEqual(observed.refresh['coverage']['counts']['tracking'], 0)
        # The denied directory is retried; the next refresh is not forced to
        # discard the whole index merely because coverage was partial.
        recovered = self.scan()
        self.assertEqual(recovered.refresh['mode'], 'incremental')
        self.assertEqual(recovered.status, 'measured')
        self.assertTrue(recovered.refresh['cache']['reusable'])
