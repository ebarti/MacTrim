import unittest
from unittest.mock import patch

from mactrim.storage import StorageNode
from tests import test_ui as fixtures

if fixtures.MacTrimApp is not None:
    from textual.widgets import DataTable, OptionList, Static
    from mactrim.ui import MacTrimApp, highlighted_path
else:
    MacTrimApp = object


class ObservedApp(MacTrimApp):
    """Observe every highlight, including transient transitions hidden by final state."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.highlights = []

    def on_data_table_row_highlighted(self, event):
        if event.control.id in {'storage-table', 'history-table'}:
            self.highlights.append((event.control.id, str(event.row_key.value)))

    def on_option_list_option_highlighted(self, event):
        if event.control.id in {'chart', 'history-chart'}:
            self.highlights.append((event.control.id, event.option.id))


@unittest.skipIf(fixtures.MacTrimApp is None, 'Native UI requires the isolated Textual project environment')
class StableSelectionTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = fixtures.NativeUITests.asyncSetUp
    asyncTearDown = fixtures.NativeUITests.asyncTearDown

    def app(self, tab):
        return ObservedApp(plan=self.plan, state=self.state, config=self.config,
                           storage_root=self.data, initial_tab=tab)

    async def test_storage_refresh_reorder_and_chart_navigation(self):
        app = self.app('storage')
        with patch.object(app, 'storage_worker'), patch.object(app, 'history_worker'):
            async with app.run_test(size=(140, 44)) as pilot:
                root = StorageNode('/fixture', 'fixture', status='scanning', allocated=10000)
                root.children = [StorageNode('/fixture/%s' % i, str(i), status='scanning',
                                             allocated=(20-i)*100) for i in range(20)]
                app.storage_path = app.storage_scan_path = root.path
                app.storage_update(root, app.storage_generation, False)
                await pilot.pause()
                table = app.query_one('#storage-table', DataTable)
                chart = app.query_one('#chart', OptionList)
                table.focus()
                await pilot.press('down')
                selected = highlighted_path(table)
                self.assertEqual(selected, '/fixture/1')
                old_option = chart.get_option_at_index(chart.highlighted)
                old_top_key = table.coordinate_to_cell_key((0, 0)).row_key
                app.highlights.clear()
                for index in range(10):
                    # A changing sort order must preserve identity, not row number.
                    root.children[2].allocated = 2500 if index % 2 else 500
                    app.storage_update(root, app.storage_generation, False)
                    await pilot.pause(.02)
                    self.assertEqual(highlighted_path(table), selected)
                    self.assertEqual(chart.get_option_at_index(chart.highlighted).id, selected)
                    self.assertIn(selected, str(app.query_one('#storage-detail', Static).content))
                self.assertEqual(app.highlights, [])
                # Neither a stale graph option nor a superseded row event may navigate.
                app.chart_highlight(OptionList.OptionHighlighted(chart, old_option, 1))
                app.storage_highlight(DataTable.RowHighlighted(table, 0, old_top_key))
                self.assertEqual(highlighted_path(table), selected)
                root.children[1].allocated = 1
                app.storage_update(root, app.storage_generation, False)
                await pilot.pause()
                self.assertEqual(highlighted_path(table), selected)
                self.assertIsNone(chart.highlighted)  # selected item is outside the graph's top 15
                chart.focus()
                await pilot.press('down')
                self.assertEqual(highlighted_path(table), chart.get_option_at_index(chart.highlighted).id)
                self.assertIs(app.focused, chart)
                count = len(app.highlights)
                await pilot.pause(.1)
                self.assertEqual(len(app.highlights), count)  # no ongoing message feedback
                # If the selected row disappears, fall back once to a valid row.
                removed = highlighted_path(table)
                root.children = [child for child in root.children if child.path != removed]
                app.storage_update(root, app.storage_generation, False)
                await pilot.pause()
                self.assertNotEqual(highlighted_path(table), removed)
                self.assertIn(highlighted_path(table), [child.path for child in root.children])

    async def test_history_refresh_reorder_and_chart_navigation(self):
        app = self.app('history')
        with patch.object(app, 'storage_worker'), patch.object(app, 'history_worker'):
            async with app.run_test(size=(140, 44)) as pilot:
                rows = [dict(path='/fixture/%s' % i, status='comparable', delta=20-i, percent=10,
                             before=100, after=120-i, recent={}, overlaps_parent=False) for i in range(20)]
                app.history_result = {'rows': rows, 'note': ''}
                app.history_catalog = {'snapshots': [], 'allocated_bytes': 0, 'limit_bytes': 16777216, 'issues': []}
                app.refresh_history()
                await pilot.pause()
                table = app.query_one('#history-table', DataTable)
                chart = app.query_one('#history-chart', OptionList)
                table.focus()
                await pilot.press('down')
                selected = highlighted_path(table)
                self.assertEqual(selected, '/fixture/1')
                old_option = chart.get_option_at_index(chart.highlighted)
                app.highlights.clear()
                for index in range(10):
                    rows[2]['delta'] = 30 if index % 2 else 10
                    app.refresh_history()
                    await pilot.pause(.02)
                    self.assertEqual(highlighted_path(table), selected)
                    self.assertEqual(chart.get_option_at_index(chart.highlighted).id, selected)
                self.assertEqual(app.highlights, [])
                app.history_chart_highlight(OptionList.OptionHighlighted(chart, old_option, 1))
                self.assertEqual(highlighted_path(table), selected)
                rows[1]['delta'] = -100
                app.refresh_history()
                await pilot.pause()
                self.assertEqual(highlighted_path(table), selected)
                self.assertIsNone(chart.highlighted)
                chart.focus()
                await pilot.press('down')
                self.assertEqual(highlighted_path(table), chart.get_option_at_index(chart.highlighted).id)
                self.assertIs(app.focused, chart)
                count = len(app.highlights)
                await pilot.pause(.1)
                self.assertEqual(len(app.highlights), count)
