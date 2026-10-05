import asyncio
import copy
import threading
import unittest
from unittest.mock import patch

from tests import test_ui as fixtures
from mactrim.storage import complete, progress_snapshot

try:
    from mactrim.ui import CancelScan, MacTrimApp
    from textual.widgets import Static, TabbedContent
except ImportError:
    MacTrimApp = None


@unittest.skipIf(MacTrimApp is None, 'Native UI requires the isolated Textual project environment')
class CancellationTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = fixtures.NativeUITests.asyncSetUp
    asyncTearDown = fixtures.NativeUITests.asyncTearDown
    wait_for = fixtures.NativeUITests.wait_for
    app = fixtures.NativeUITests.app

    def storage_worker(self, calls, release):
        observed = complete(self.data)
        def inventory(path, state, config, *, cancel, progress, full):
            calls.append(cancel)
            node = copy.deepcopy(observed)
            progress(progress_snapshot(node, 'Enumerating metadata', str(path)), node)
            while not cancel.wait(.01) and not release.is_set():
                progress(progress_snapshot(node, 'Enumerating metadata', str(path)), node)
            if cancel.is_set():
                node.status = 'cancelled'
                node.issues = ['Cancelled; unvisited scopes remain unknown']
            return node
        return inventory

    async def test_escape_never_cancels_and_confirmation_targets_only_named_scan(self):
        calls, release, cleanup_tokens, cleanup_progress = [], threading.Event(), [], []
        template = self.plan
        class SlowScanner:
            def __init__(self, config, state, progress, cancel):
                self.cancel = cancel
                cleanup_tokens.append(cancel)
                cleanup_progress.append(progress)
            def run(self):
                self.cancel.wait(15)
                return dict(template, cancelled=self.cancel.is_set())
        app = MacTrimApp(state=self.state, config=self.config, storage_root=self.data, scanner_factory=SlowScanner)
        with patch('mactrim.ui.inventory', side_effect=self.storage_worker(calls, release)), patch('mactrim.ui.capacities', return_value=[]):
            async with app.run_test(size=(140, 44)) as pilot:
                try:
                    await self.wait_for(pilot, lambda: bool(calls) and bool(cleanup_tokens) and app.storage_node is not None)
                    await pilot.press('escape')
                    self.assertFalse(calls[0].is_set())
                    self.assertFalse(cleanup_tokens[0].is_set())
                    app.query_one('#tabs', TabbedContent).active = 'storage'
                    app.query_one('#storage-table').focus()
                    await pilot.press('escape', 'ctrl+x')
                    self.assertIsInstance(app.screen, CancelScan)
                    self.assertEqual(app.screen.scope, 'storage')
                    self.assertIn(str(self.data), ' '.join(str(widget.content) for widget in app.screen.query(Static)))
                    self.assertFalse(calls[0].is_set())
                    await asyncio.to_thread(cleanup_progress[0], 'candidate', template['candidates'][0])
                    await pilot.pause(.2)
                    self.assertIsInstance(app.screen, CancelScan)
                    self.assertGreater(app.query_main('#cleanup-table').row_count, 0)
                    await pilot.press('n')
                    self.assertNotIsInstance(app.screen, CancelScan)
                    self.assertFalse(calls[0].is_set())
                    await pilot.press('ctrl+x', 'escape')
                    self.assertFalse(calls[0].is_set())
                    # Enter defaults to No; a deliberate affirmative answer is required.
                    await pilot.press('ctrl+x', 'enter')
                    self.assertFalse(calls[0].is_set())
                    await pilot.click('#cancel-storage')
                    self.assertIsInstance(app.screen, CancelScan)
                    await pilot.click('#cancel-yes')
                    await self.wait_for(pilot, lambda: not app.storage_measuring)
                    self.assertEqual(app.storage_node.status, 'cancelled')
                    self.assertIn('Storage stopped', str(app.query_one('#storage-status', Static).content))
                    self.assertFalse(cleanup_tokens[0].is_set())
                    # Redraws, tabs, and idle time must not restart the stopped worker.
                    for tab in ('history', 'cleanup', 'storage'):
                        app.query_one('#tabs', TabbedContent).active = tab
                        await pilot.pause(.1)
                    await pilot.resize_terminal(120, 40)
                    app.query_one('#metric').value = 'logical'
                    await pilot.pause(.2)
                    self.assertEqual(len(calls), 1)
                    self.assertFalse(app.storage_measuring)
                    await pilot.resize_terminal(140, 44)
                    self.assertTrue(await pilot.click('#--content-tab-cleanup'))
                    await self.wait_for(pilot, lambda: app.query_main('#cancel-scan').region.width > 0)
                    self.assertTrue(await pilot.click('#cancel-scan'))
                    self.assertIsInstance(app.screen, CancelScan)
                    self.assertEqual(app.screen.scope, 'cleanup')
                    self.assertFalse(cleanup_tokens[0].is_set())
                    await pilot.press('y')
                    await self.wait_for(pilot, lambda: not app.scanning)
                    self.assertTrue(cleanup_tokens[0].is_set())
                    self.assertEqual(len(calls), 1)
                finally:
                    release.set()
                    app.storage_cancel.set()
                    app.scan_cancel.set()

    async def test_stale_confirmation_cannot_cancel_replacement_or_finished_scan(self):
        calls, release = [], threading.Event()
        app = self.app(initial_tab='storage')
        with patch('mactrim.ui.inventory', side_effect=self.storage_worker(calls, release)), patch('mactrim.ui.capacities', return_value=[]):
            async with app.run_test(size=(140, 44)) as pilot:
                try:
                    await self.wait_for(pilot, lambda: len(calls) == 1 and app.storage_node is not None)
                    app.query_one('#storage-table').focus()
                    await pilot.press('ctrl+x')
                    self.assertIsInstance(app.screen, CancelScan)
                    await pilot.press('ctrl+x')
                    self.assertEqual(len(app.screen_stack), 2)
                    app.start_storage(self.data, full=True)
                    await self.wait_for(pilot, lambda: len(calls) == 2)
                    self.assertTrue(calls[0].is_set())
                    await pilot.press('y')
                    self.assertFalse(calls[1].is_set())
                    self.assertTrue(app.storage_measuring)
                    await pilot.press('ctrl+x')
                    self.assertIsInstance(app.screen, CancelScan)
                    release.set()
                    await self.wait_for(pilot, lambda: not app.storage_measuring)
                    await pilot.press('y')
                    self.assertFalse(calls[1].is_set())
                    self.assertEqual(app.storage_node.status, 'measured')
                    await pilot.press('ctrl+x')
                    self.assertNotIsInstance(app.screen, CancelScan)
                    self.assertEqual(len(calls), 2)
                finally:
                    release.set()
                    app.storage_cancel.set()
