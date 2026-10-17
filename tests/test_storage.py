import os
from pathlib import Path
import tempfile
import threading
import unittest
from mactrim.storage import complete, page, PAGE_SIZE
from mactrim.config import defaults
from mactrim.history import History
from mactrim.state import State

class CompleteStorageTests(unittest.TestCase):
    def test_old_limits_are_not_measurement_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for index in range(50010):
                (root / str(index)).touch()
            deep = root
            for _ in range(70):
                deep /= 'd'
                deep.mkdir()
            (deep / 'payload').write_bytes(b'x' * 8192)
            result = complete(root, lazy=False)
            self.assertEqual(result.status, 'measured', result.issues)
            self.assertGreater(result.entries, 50000)
            self.assertEqual(len(result.children), 1)
            rows, more = page(result)
            self.assertEqual(len(rows), PAGE_SIZE)
            self.assertTrue(more)
            cursor = result
            while cursor.children:
                cursor = cursor.children[0]
            self.assertEqual(cursor.path, str(deep))
            self.assertGreaterEqual(cursor.logical, 8192)

    def test_hardlinks_sparse_denial_symlinks_and_cancel(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'one').mkdir(); (root / 'two').mkdir()
            data = root / 'one' / 'data'
            data.write_bytes(b'x' * 4096)
            os.link(data, root / 'two' / 'alias')
            os.symlink(root, root / 'loop')
            with (root / 'sparse').open('wb') as stream:
                stream.truncate(1024 * 1024)
            result = complete(root)
            self.assertEqual(result.status, 'measured', result.issues)
            self.assertEqual(result.exclusions['Already accounted hardlink'], 1)
            self.assertLess(result.allocated, result.logical)
            (root / 'two').chmod(0)
            try:
                denied = complete(root)
                self.assertEqual(denied.status, 'partial')
                self.assertGreater(denied.counters['denied'], 0)
            finally:
                (root / 'two').chmod(0o700)
            cancel = threading.Event(); cancel.set()
            self.assertEqual(complete(root, cancel=cancel).status, 'cancelled')

    def test_complete_history_never_compares_sampled_policy(self):
        from mactrim.measurement import measure
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); (root / 'data').mkdir()
            state = State(root / 'state').prepare()
            history = History(state, defaults())
            old = history.capture(measure(root / 'data', storage=True), [])
            new = history.capture(complete(root / 'data'), [])
            result = history.compare(old['id'], new['id'])
            self.assertEqual(result['rows'], [])
            self.assertIn('Incompatible', result['issues'][0])
