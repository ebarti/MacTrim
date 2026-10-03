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

    def test_budget_does_not_allocate_unbounded_unmeasured_children(self):
        for index in range(200):
            (self.root / str(index)).write_bytes(b"x")
        node = measure(self.root, max_entries=1)
        self.assertEqual(node.status, "partial")
        self.assertLessEqual(len(node.children), 1)
        self.assertEqual(node.logical, 0)

    def test_root_user_front_door_changes_subtree_device_context(self):
        from contextlib import contextmanager
        from types import SimpleNamespace
        users = self.root / "Users"
        users.mkdir()
        (users / "person").mkdir()
        (users / "person" / "a").write_bytes(b"x" * 23)
        real_stat, real_fstat, real_lstat = os.stat, os.fstat, os.lstat
        root_ino = self.root.stat().st_ino
        def adjusted(value):
            fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
            fields["st_dev"] = 1 if value.st_ino == root_ino else 2
            return SimpleNamespace(**fields)
        @contextmanager
        def root_fd(path):
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                yield fd
            finally:
                os.close(fd)
        def lstat(path):
            return adjusted(real_lstat(self.root)) if str(path) == "/" else adjusted(real_lstat(path))
        with patch("mactrim.measurement.directory_fd", root_fd), patch("mactrim.measurement.ancestor_identity"), patch("mactrim.measurement.os.lstat", side_effect=lstat), patch("mactrim.measurement.os.fstat", side_effect=lambda fd: adjusted(real_fstat(fd))), patch("mactrim.measurement.os.stat", side_effect=lambda *args, **kwargs: adjusted(real_stat(*args, **kwargs))):
            node = measure("/", storage=True, independent_children=True)
        self.assertEqual(node.logical, 23)
        self.assertEqual(node.children[0].children[0].logical, 23)

    def test_capacity_root_exposes_data_separately(self):
        with patch('mactrim.measurement.Path.exists', return_value=True):
            items = capacities('/')
        self.assertEqual([item['path'] for item in items], ['/', '/System/Volumes/Data'])
        self.assertTrue(all('status' in item for item in items))
