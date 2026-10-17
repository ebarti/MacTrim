import threading
import unittest
from unittest.mock import patch

from tests import test_ui as fixtures
from mactrim.incremental import inventory
from mactrim.storage_cache import Cache


@unittest.skipIf(fixtures.MacTrimApp is None, 'Native Textual environment required')
class NavigationTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = fixtures.NativeUITests.asyncSetUp
    asyncTearDown = fixtures.NativeUITests.asyncTearDown
    wait_for = fixtures.NativeUITests.wait_for
    app = fixtures.NativeUITests.app

    async def test_drill_and_parent_preserve_worker_and_save_original_scope(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def running(path, *args, **kwargs):
            calls.append(path)
            publish = kwargs['progress']
            def progress(snapshot, current):
                publish(snapshot, current)
                if snapshot.children and not entered.is_set():
                    entered.set()
                    release.wait(12)
            progress.view = publish.view
            kwargs['progress'] = progress
            return inventory(path, *args, **kwargs)
        app = self.app(initial_tab='storage')
        with patch('mactrim.ui.inventory', side_effect=running):
            async with app.run_test(size=(140, 44)) as pilot:
                try:
                    await self.wait_for(pilot, entered.is_set)
                    token, generation = app.storage_cancel, app.storage_generation
                    child = str(self.data / 'growing')
                    for path in (child, str(self.data), child):
                        app.start_storage(path)
                        await pilot.pause(.05)
                        self.assertEqual(app.storage_path, path)
                        self.assertIs(app.storage_cancel, token)
                        self.assertFalse(token.is_set())
                        self.assertEqual(app.storage_generation, generation)
                        self.assertEqual(calls, [str(self.data)])
                    release.set()
                    await self.wait_for(pilot, lambda: not app.storage_measuring)
                    self.assertEqual(app.storage_node.path, child)
                    self.assertEqual(app.storage_inventory.path, str(self.data))
                    saved = Cache(self.state, self.config['storage_cache']).read(details=False)[0]
                    self.assertEqual(saved['scope'], str(self.data))
                    app.start_storage(str(self.data))
                    self.assertEqual(app.storage_node.path, str(self.data))
                    self.assertEqual(calls, [str(self.data)])
                finally:
                    release.set()

    async def test_lazy_details_wait_for_main_scan_and_never_replace_its_index(self):
        dependencies = self.data / 'node_modules'
        (dependencies / 'package' / 'lib').mkdir(parents=True)
        (dependencies / 'package' / 'lib' / 'payload').write_bytes(b'x' * 8192)
        entered, release = threading.Event(), threading.Event()
        calls, committed = [], []
        def running(path, state, config, **kwargs):
            calls.append((path,state))
            if state is not None:
                publish = kwargs['progress']
                def progress(snapshot,current):
                    publish(snapshot,current)
                    if any(child.path==str(dependencies) for child in snapshot.children) and not entered.is_set():
                        entered.set(); release.wait(12)
                progress.view = publish.view
                kwargs['progress'] = progress
            result = inventory(path,state,config,**kwargs)
            if state is not None:
                committed.append((self.state.path/'storage-cache'/'index.json.gz').read_bytes())
            return result
        app = self.app(initial_tab='storage')
        with patch('mactrim.ui.inventory',side_effect=running):
            async with app.run_test(size=(140,44)) as pilot:
                try:
                    await self.wait_for(pilot,entered.is_set)
                    token=app.storage_cancel
                    app.drill(str(dependencies))
                    await pilot.pause(.05)
                    self.assertEqual(len(calls),1)
                    self.assertFalse(token.is_set())
                    release.set()
                    await self.wait_for(pilot,lambda:len(calls)==2 and not app.storage_measuring,timeout=12)
                    self.assertEqual(calls[1],(str(dependencies),None))
                    self.assertEqual(app.storage_inventory.path,str(self.data))
                    self.assertEqual(app.storage_node.path,str(dependencies))
                    self.assertFalse(app.storage_node.details_deferred)
                    self.assertTrue(app.storage_node.children)
                    self.assertEqual((self.state.path/'storage-cache'/'index.json.gz').read_bytes(),committed[0])
                    app.start_storage(str(self.data))
                    app.start_storage(str(dependencies))
                    self.assertEqual(len(calls),2,'Repeated navigation reloaded existing details')
                finally: release.set()
