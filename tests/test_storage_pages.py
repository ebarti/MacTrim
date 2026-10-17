"""Global page-order regressions; all filesystem data is disposable."""
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from mactrim.regions import Cancelled
from mactrim.storage import (complete, page, page_offset, directory_page,
                             progress_snapshot, StorageNode, PAGE_SIZE, storage_order)


class StoragePageTests(unittest.TestCase):
    def test_largest_folder_and_file_are_ranked_before_paging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for index in range(PAGE_SIZE + 5):
                (root / ('folder-%04d' % index)).mkdir()
            with os.scandir(root) as entries:
                largest = root / list(entries)[-1].name
            (largest / 'payload').write_bytes(b'x' * 16384)
            (root / 'large-file').write_bytes(b'x' * 32768)
            measured = complete(root)
            first, more = page(measured)
            self.assertEqual(first[0].name, 'large-file')
            self.assertEqual(first[1].path, str(largest))
            self.assertTrue(more)
            following, more = page(measured, PAGE_SIZE)
            self.assertFalse(more)
            combined = first + following
            self.assertEqual(len(combined), PAGE_SIZE + 6)
            self.assertEqual(len({row.path for row in combined}), len(combined))
            self.assertEqual(combined, sorted(combined, key=storage_order()))
            self.assertEqual(measured.export()['children'][0]['path'], str(largest))
            self.assertEqual(page_offset(measured, str(largest)), 0)

    def test_logical_allocated_and_name_orders_include_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'dense').write_bytes(b'x' * (1024 * 1024))
            with (root / 'sparse').open('wb') as stream:
                stream.seek(16 * 1024 * 1024); stream.write(b'x' * 4096)
                stream.flush(); os.fsync(stream.fileno())
            measured = complete(root)
            self.assertEqual(page(measured, metric='logical')[0][0].name, 'sparse')
            self.assertEqual(page(measured, metric='allocated')[0][0].name, 'dense')
            self.assertEqual([row.name for row in page(measured, order='name')[0]], ['dense', 'sparse'])

    def test_name_order_can_locate_a_chart_directory_on_a_later_page(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for index in range(PAGE_SIZE + 3):
                (root / ('a-%04d' % index)).touch()
            (root / 'z-largest').mkdir()
            (root / 'z-largest' / 'payload').write_bytes(b'x' * 8192)
            measured = complete(root)
            target = str(root / 'z-largest')
            offset = page_offset(measured, target, order='name')
            self.assertEqual(offset, PAGE_SIZE)
            self.assertIn(target, [row.path for row in page(measured, offset, order='name')[0]])

    def test_listing_is_immediate_only_and_cooperatively_cancellable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'child' / 'deep').mkdir(parents=True)
            (root / 'child' / 'deep' / 'payload').write_bytes(b'x' * 8192)
            (root / 'file').write_bytes(b'x')
            measured = complete(root)
            original = os.scandir
            def immediate(fd):
                self.assertEqual(os.fstat(fd).st_ino, root.stat().st_ino)
                return original(fd)
            with patch('mactrim.storage.os.scandir', side_effect=immediate):
                self.assertEqual(len(page(measured)[0]), 2)
            cancel = threading.Event(); cancel.set()
            with self.assertRaises(Cancelled):
                page(measured, cancel=cancel)

    def test_live_snapshot_keeps_largest_directories_not_first_discovered(self):
        root = StorageNode('/fixture', 'fixture')
        root.children = [StorageNode('/fixture/%s' % i, str(i), allocated=i,
                                     status='measured') for i in range(PAGE_SIZE + 5)]
        expected = str(PAGE_SIZE + 4)
        self.assertEqual(directory_page(root)[0][0].name, expected)
        snapshot = progress_snapshot(root, 'Native size scan', root.path, completed=lambda _: True)
        self.assertEqual(len(snapshot.children), PAGE_SIZE)
        self.assertEqual(snapshot.children[0].name, expected)
        self.assertEqual(snapshot.children[0].status, 'measured')

    def test_deep_sparse_container_payload_is_included_beyond_detail_depth(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            data = root / 'Users/person/Library/Containers/com.docker.docker/Data/vms/0/data'
            data.mkdir(parents=True)
            image = data / 'Docker.raw'
            with image.open('wb') as stream:
                stream.truncate(16 * 1024 * 1024)
                stream.seek(0); stream.write(b'x' * 8192)
            measured = complete(root)
            self.assertEqual(measured.status, 'measured')
            self.assertGreaterEqual(measured.logical, image.stat().st_size)
            self.assertGreaterEqual(measured.allocated, image.stat().st_blocks * 512)
            cursor = measured
            while cursor.children:
                cursor = cursor.children[0]
            self.assertTrue(cursor.details_deferred)
            self.assertEqual(cursor.summary()['size_state'], 'measured')
            self.assertGreaterEqual(cursor.allocated, image.stat().st_blocks * 512)
            opened = complete(cursor.path)
            self.assertEqual(opened.allocated, cursor.allocated)
            self.assertEqual(opened.logical, cursor.logical)
