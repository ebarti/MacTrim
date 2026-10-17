import threading
import unittest
from unittest.mock import patch

from tests import test_ui as fixtures
from mactrim.storage import complete, PAGE_SIZE, page

if fixtures.MacTrimApp is not None:
    from textual.widgets import DataTable, OptionList, TabbedContent
    from mactrim.ui import highlighted_path


@unittest.skipIf(fixtures.MacTrimApp is None, 'Native Textual environment required')
class StoragePageUITests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = fixtures.NativeUITests.asyncSetUp
    asyncTearDown = fixtures.NativeUITests.asyncTearDown
    wait_for = fixtures.NativeUITests.wait_for
    app = fixtures.NativeUITests.app

    async def test_largest_directory_is_visible_and_chart_can_select_across_pages(self):
        for index in range(PAGE_SIZE + 3):
            (self.data / ('a-%04d' % index)).mkdir()
        largest = self.data / 'z-largest'; largest.mkdir()
        (largest / 'payload').write_bytes(b'x' * 16384)
        node = complete(self.data)
        app = self.app(initial_tab='storage')
        with patch.object(app, 'storage_worker'), patch.object(app, 'history_worker'):
            async with app.run_test(size=(140, 44)) as pilot:
                app.storage_update(node, app.storage_generation, True)
                await self.wait_for(pilot, lambda: not app.storage_page_loading)
                table = app.query_one('#storage-table', DataTable)
                chart = app.query_one('#chart', OptionList)
                self.assertEqual(app.storage_nodes[0].path, str(largest))
                self.assertEqual(chart.get_option_at_index(0).id, str(largest))
                self.assertEqual(highlighted_path(table), str(largest))
                app.query_one('#storage-sort').value = 'name'
                await pilot.pause(.1)
                await self.wait_for(pilot, lambda: not app.storage_page_loading)
                self.assertNotIn(str(largest), [row.path for row in app.storage_nodes])
                option = chart.get_option_at_index(0)
                chart.highlighted = 0
                app.chart_highlight(OptionList.OptionHighlighted(chart, option, 0))
                await self.wait_for(pilot, lambda: not app.storage_page_loading)
                self.assertEqual(app.storage_offset, PAGE_SIZE)
                self.assertEqual(highlighted_path(table), str(largest))
                with patch.object(app, 'start_storage') as start:
                    app.drill(str(largest))
                    start.assert_called_once_with(str(largest))

    async def test_listing_runs_off_ui_thread_and_late_pages_are_rejected(self):
        entered, release = threading.Event(), threading.Event()
        ui_thread = threading.get_ident()
        def waiting(*args, **kwargs):
            self.assertNotEqual(threading.get_ident(), ui_thread)
            entered.set(); release.wait(12)
            return page(*args, **kwargs)
        node = complete(self.data)
        app = self.app(initial_tab='storage')
        with patch.object(app, 'storage_worker'), patch.object(app, 'history_worker'), patch('mactrim.ui.page', side_effect=waiting):
            async with app.run_test(size=(140, 44)) as pilot:
                try:
                    app.storage_update(node, app.storage_generation, True)
                    await self.wait_for(pilot, entered.is_set)
                    generation = app.storage_page_generation
                    app.query_one('#tabs', TabbedContent).active = 'history'
                    await pilot.pause(.05)
                    self.assertEqual(app.query_one('#tabs', TabbedContent).active, 'history')
                    app.storage_page_generation += 1
                    app.storage_page_update(node.path, 0, [], False, None, generation, app.storage_generation)
                    self.assertTrue(app.storage_page_rows)
                    self.assertTrue(app.storage_page_loading)
                finally:
                    app.storage_page_cancel.set()
                    release.set()
