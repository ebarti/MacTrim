import unittest
from unittest.mock import patch
from tests import test_ui as fixtures
from mactrim.storage import complete

try:
    from mactrim.ui import index_save_status, MacTrimApp
    from textual.widgets import Static
except ImportError:
    MacTrimApp = None


@unittest.skipIf(MacTrimApp is None, 'Native UI requires the isolated Textual project environment')
class SaveStatusTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = fixtures.NativeUITests.asyncSetUp
    asyncTearDown = fixtures.NativeUITests.asyncTearDown
    app = fixtures.NativeUITests.app

    async def test_finished_partial_scan_displays_actual_persistence_result(self):
        node = complete(self.data)
        node.status = 'partial'
        app = self.app(initial_tab='storage')
        with patch.object(app, 'storage_worker'), patch.object(app, 'history_worker'):
            async with app.run_test(size=(140, 44)) as pilot:
                for saved, expected in [
                    ({'stored': True, 'complete_index': True, 'reusable': True}, 'INDEX SAVED'),
                    ({'stored': True, 'complete_index': True, 'reusable': False}, 'OBSERVATION SAVED'),
                    ({'stored': True, 'complete_index': False, 'reusable': False}, 'TOTALS SAVED ONLY'),
                    ({'stored': False, 'reason': 'Save error'}, 'INDEX NOT SAVED'),
                ]:
                    node.refresh = {'cache': saved, 'mode': 'full'}
                    app.storage_update(node, app.storage_generation, True)
                    await pilot.pause(.05)
                    footer = str(app.query_one('#storage-status', Static).content)
                    summary = str(app.query_one('#storage-summary', Static).content)
                    self.assertIn('Scan finished (PARTIAL)', footer)
                    self.assertIn(expected, footer)
                    self.assertIn(expected, summary)
                    self.assertFalse(app.storage_measuring)

    async def test_coverage_dialog_shows_blocked_path_and_esc_only_closes_dialog(self):
        from mactrim.storage import coverage_report
        from mactrim.ui import Coverage
        node = complete(self.data)
        node.status = 'partial'
        blocked = node.children[0]
        blocked.status = 'denied'
        blocked.issues = ['Operation not permitted']
        node.refresh = {'coverage': coverage_report(node)}
        app = self.app(initial_tab='storage')
        with patch.object(app, 'storage_worker'), patch.object(app, 'history_worker'):
            async with app.run_test(size=(140, 44)) as pilot:
                app.storage_update(node, app.storage_generation, True)
                await pilot.click('#storage-coverage')
                await pilot.pause(.05)
                self.assertIsInstance(app.screen, Coverage)
                content = '\n'.join(str(widget.content) for widget in app.screen.query(Static))
                self.assertIn(blocked.path, content)
                self.assertIn('Operation not permitted', content)
                await pilot.press('escape')
                self.assertNotIsInstance(app.screen, Coverage)
                self.assertFalse(app.storage_cancel.is_set())

    async def test_running_scan_displays_full_fallback_reason(self):
        from mactrim.storage import progress_snapshot
        node = progress_snapshot(complete(self.data), 'Enumerating metadata', str(self.data))
        node.refresh = {'mode': 'full', 'reason': 'Filesystem event-history UUID changed; full reconciliation required'}
        app = self.app(initial_tab='storage')
        with patch.object(app, 'storage_worker'), patch.object(app, 'history_worker'):
            async with app.run_test(size=(140, 44)) as pilot:
                app.storage_update(node, app.storage_generation, False)
                summary = str(app.query_one('#storage-summary', Static).content)
                self.assertIn('FULL', summary)
                self.assertIn('event-history UUID changed', summary)
                self.assertTrue(app.storage_measuring)

    async def test_running_scan_shows_native_size_phase(self):
        from mactrim.storage import progress_snapshot
        node = progress_snapshot(complete(self.data), 'Enumerating metadata', str(self.data))
        app = self.app(initial_tab='storage')
        with patch.object(app, 'storage_worker'), patch.object(app, 'history_worker'):
            async with app.run_test(size=(140, 44)) as pilot:
                for traversal, expected in [('native', 'native size scan')]:
                    node.progress.update(traversal=traversal, depth=2)
                    app.storage_update(node, app.storage_generation, False)
                    summary = str(app.query_one('#storage-summary', Static).content)
                    self.assertIn(expected, summary)
                    self.assertIn('SCANNING; observed lower bounds', summary)
                    self.assertTrue(app.storage_measuring)

    async def test_collapsed_folder_displays_measured_recursive_size(self):
        dependencies = self.data / 'node_modules'
        (dependencies / 'package').mkdir(parents=True)
        (dependencies / 'package/payload').write_bytes(b'x' * 8192)
        node = complete(self.data)
        app = self.app(initial_tab='storage')
        with patch.object(app, 'storage_worker'), patch.object(app, 'history_worker'):
            async with app.run_test(size=(140, 44)) as pilot:
                app.storage_update(node, app.storage_generation, True)
                app.storage_selected(str(dependencies))
                detail = str(app.query_one('#storage-detail', Static).content)
                self.assertNotIn('Not measured', detail)
                self.assertIn('8.', detail)
                self.assertIn('Recursive size included', detail)
                self.assertNotIn('0.0 B', detail)
                self.assertIn('MEASURED', detail)
                from mactrim.storage import coverage_report
                node.refresh = {'coverage': coverage_report(node)}
                app.storage_update(node, app.storage_generation, True)
                await pilot.click('#storage-coverage')
                content = '\n'.join(str(widget.content) for widget in app.screen.query(Static))
                self.assertIn('Collapsed folders include recursive sizes', content)

    async def test_completed_directory_stays_measured_while_background_scan_continues(self):
        from mactrim.storage import progress_snapshot
        root = complete(self.data)
        selected = root.children[0]
        snapshot = progress_snapshot(root, 'Native size scan', root.path)
        snapshot.view = progress_snapshot(selected, 'Native size scan', root.path)
        snapshot.view.status = 'measured'
        snapshot.view.progress.update(scope_finished=True, traversal='native')
        app = self.app(initial_tab='storage')
        with patch.object(app, 'storage_worker'), patch.object(app, 'history_worker'):
            async with app.run_test(size=(140, 44)) as pilot:
                app.storage_path = selected.path
                token, generation = app.storage_cancel, app.storage_generation
                app.storage_update(snapshot, generation, False)
                summary = str(app.query_one('#storage-summary', Static).content)
                self.assertIn('MEASURED; background scan continues', summary)
                self.assertTrue(app.storage_measuring)
                self.assertIs(app.storage_cancel, token)
                self.assertFalse(token.is_set())
                self.assertEqual(app.storage_generation, generation)
