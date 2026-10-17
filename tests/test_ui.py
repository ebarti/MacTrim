import asyncio
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

try:
    from mactrim.ui import MacTrimApp, Approval
    from textual.widgets import DataTable, Input, Static, TabbedContent
except ImportError:
    MacTrimApp = None

from mactrim.activity import Activity
from mactrim.config import read_config
from mactrim.demo import create
from mactrim.executor import Executor
from mactrim.scanner import Scanner
from mactrim.state import State


@unittest.skipIf(MacTrimApp is None, 'Native UI requires the isolated Textual project environment')
class NativeUITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        parent = Path.cwd() / 'evidence'
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.root = Path(self.temporary.name)
        create(self.root / 'demo')
        self.state = State(self.root / 'state').prepare()
        self.config = read_config(self.root / 'demo' / 'config.json', self.state.path)
        self.config['storage_max_files'] = 1000
        self.data = self.root / 'storage'
        (self.data / 'growing').mkdir(parents=True)
        (self.data / 'growing' / 'file.txt').write_bytes(b'x' * 20)
        with patch('mactrim.apps.services', return_value=(set(), [])):
            self.plan = Scanner(self.config, self.state, Activity(True)).run()

    async def asyncTearDown(self):
        self.temporary.cleanup()

    async def wait_for(self, pilot, predicate, timeout=6):
        start = time.monotonic()
        while not predicate():
            if time.monotonic() - start > timeout:
                self.fail('UI worker did not reach expected fixture state')
            await pilot.pause(.05)
        await pilot.pause(.1)

    def app(self, **kwargs):
        return MacTrimApp(plan=self.plan, state=self.state, config=self.config, storage_root=self.data,
                          executor_factory=lambda state: Executor(state, activity_provider=lambda: Activity(True)), **kwargs)

    async def test_capacity_and_live_totals_visible_before_worker_finishes(self):
        from mactrim.storage import complete, progress_snapshot
        result = complete(self.data)
        snapshot = progress_snapshot(result, 'Classifying unsettled directories', str(self.data))
        snapshot.children[0].status = 'scanning'
        entered, release = threading.Event(), threading.Event()
        def pending_inventory(*args, **kwargs):
            kwargs['progress'](snapshot, snapshot)
            entered.set()
            release.wait(10)
            return result
        capacities = [{'label': 'Fixture filesystem', 'path': '/', 'status': 'measured',
                       'used': 100000, 'available': 100000, 'total': 200000}]
        app = self.app(initial_tab='storage')
        with patch('mactrim.ui.capacities', return_value=capacities), patch('mactrim.ui.inventory', side_effect=pending_inventory):
            async with app.run_test(size=(140, 44)) as pilot:
                try:
                    await self.wait_for(pilot, lambda: entered.is_set() and app.storage_node is not None)
                    self.assertTrue(app.storage_measuring)
                    self.assertEqual(app.capacity_rows, capacities)
                    summary = str(app.query_one('#storage-summary', Static).render())
                    status = str(app.query_one('#storage-status', Static).render())
                    self.assertIn('visited %s' % result.counters['visited'], summary)
                    self.assertIn('observed lower bounds', summary)
                    self.assertIn('Classifying unsettled directories', status)
                    self.assertIn(str(self.data), status)
                    self.assertGreater(app.storage_node.allocated, 0)
                    self.assertTrue(app.query_one('#chart')._options)
                    self.assertEqual(app.storage_nodes[0].status, 'scanning')
                    app.cancel_storage()
                    self.assertTrue(app.storage_cancel.is_set())
                    self.assertIn('Cancellation requested', str(app.query_one('#storage-status', Static).render()))
                finally:
                    release.set()
                await self.wait_for(pilot, lambda: not app.storage_measuring)

    async def test_native_tabs_selection_detail_and_exact_approval_refusal(self):
        app = self.app()
        async with app.run_test(size=(140,44)) as pilot:
            await self.wait_for(pilot, lambda: not app.storage_measuring)
            self.assertEqual(app.selected, set())
            table = app.query_one('#cleanup-table', DataTable)
            report_index = next(i for i, item in enumerate(app.visible_items()) if not item['eligible'])
            table.move_cursor(row=report_index)
            app.action_toggle()
            self.assertEqual(app.selected, set())
            index = next(i for i, item in enumerate(app.visible_items()) if item['eligible'])
            table.move_cursor(row=index)
            app.action_toggle()
            self.assertEqual(len(app.selected), 1)
            app.action_quarantine()
            await self.wait_for(pilot, lambda: isinstance(app.screen, Approval))
            app.screen.query_one('#approval-input', Input).value = 'yes'
            app.screen.confirm()
            self.assertIsInstance(app.screen, Approval)
            self.assertEqual(self.state.journals(), [])
            await pilot.press('escape')
            await pilot.pause(.2)
            self.assertFalse(app.busy)
            app.query_one('#search', Input).value = 'does-not-exist'
            await pilot.pause(.2)
            self.assertEqual(table.row_count, 0)
            await pilot.resize_terminal(90,30)
            self.assertEqual(app.query_one('#tabs', TabbedContent).active, 'cleanup')

    async def test_storage_chart_list_shared_navigation_and_history_growth_drill(self):
        app = self.app(initial_tab='storage')
        async with app.run_test(size=(140,44)) as pilot:
            await self.wait_for(pilot, lambda: app.history_catalog is not None and len(app.history_catalog['snapshots']) == 1)
            self.assertEqual({node.path for node in app.storage_nodes}, {option.id for option in app.query_one('#chart')._options})
            (self.data / 'growing' / 'file.txt').write_bytes(b'x' * 120)
            app.start_storage(self.data)
            await self.wait_for(pilot, lambda: not app.storage_measuring)
            app.capture_current()
            await self.wait_for(pilot, lambda: len(app.history_catalog['snapshots']) == 2)
            app.query_one('#history-metric').value = 'logical'
            await self.wait_for(pilot, lambda: app.history_result.get('metric') == 'logical')
            growing = next(row for row in app.history_rows if row['path'] == str(self.data / 'growing'))
            self.assertEqual(growing['delta'], 100)
            app.query_one('#tabs', TabbedContent).active = 'history'
            app.query_one('#history-table', DataTable).move_cursor(row=app.history_rows.index(growing))
            await pilot.pause(.1)
            app.query_one('#history-table', DataTable).focus()
            await pilot.press('enter')
            await self.wait_for(pilot, lambda: app.storage_path == str(self.data / 'growing') and not app.storage_measuring and app.query_one('#tabs', TabbedContent).active == 'storage')
            self.assertEqual(app.query_one('#tabs', TabbedContent).active, 'storage')
            app.start_storage(self.data)
            await self.wait_for(pilot, lambda: not app.storage_measuring)
            self.assertTrue(app.storage_node.recent['modified_7d'])

    async def test_growth_detail_proven_absence_overlap_and_unknown_are_presentation_only(self):
        removed = self.data / 'removed'
        removed.mkdir()
        (removed / 'file.txt').write_bytes(b'x' * 20)
        app = self.app(initial_tab='history')
        async with app.run_test(size=(140, 44)) as pilot:
            await self.wait_for(pilot, lambda: app.history_catalog is not None and len(app.history_catalog['snapshots']) == 1)
            self.assertNotIn('380', str(app.query_one('#history-summary', Static).content))
            (removed / 'file.txt').unlink()
            removed.rmdir()
            added = self.data / 'added'
            added.mkdir()
            (added / 'file.txt').write_bytes(b'x' * 30)
            app.start_storage(self.data)
            await self.wait_for(pilot, lambda: not app.storage_measuring)
            app.capture_current()
            await self.wait_for(pilot, lambda: len(app.history_catalog['snapshots']) == 2)
            rows = {row['path']: row for row in app.history_rows}
            self.assertEqual(rows[str(removed)]['status'], 'removed-directory')
            self.assertIsNone(rows[str(removed)]['after'])
            app.history_detail(str(removed))
            text = str(app.query_one('#history-detail', Static).content)
            self.assertIn('after 0 B (absent)', text)
            self.assertIn('Included in parent totals', text)
            self.assertNotIn('True', text)
            self.assertEqual(rows[str(added)]['status'], 'new-directory')
            self.assertIsNone(rows[str(added)]['before'])
            app.history_detail(str(added))
            self.assertIn('before 0 B (absent)', str(app.query_one('#history-detail', Static).content))
            app.history_detail(str(self.data))
            self.assertNotIn('Included in parent totals', str(app.query_one('#history-detail', Static).content))
            self.assertNotIn('False', str(app.query_one('#history-detail', Static).content))
            # Uncertain/partial observations retain their API values but the
            # detail must not turn missing evidence into proven zero bytes.
            for status in ('unknown', 'newly-observed'):
                row = dict(rows[str(added)], status=status, before=17, after=39)
                app.history_rows = [row]
                app.history_detail(row['path'])
                text = str(app.query_one('#history-detail', Static).content)
                self.assertIn('before unknown · after unknown', text)
                self.assertNotIn('(absent)', text)
                self.assertEqual((row['before'], row['after']), (17, 39))

    async def test_full_capture_has_no_quota_controls_and_preserves_cleanup_plan(self):
        app = self.app(initial_tab='storage')
        original_budget = self.plan['config']['storage_max_files']
        async with app.run_test(size=(140, 44)) as pilot:
            await self.wait_for(pilot, lambda: not app.storage_measuring)
                self.assertEqual(app.storage_node.collector, 'storage.on-demand.v2')
            generation = app.storage_generation
            await pilot.click('#storage-full')
            await self.wait_for(pilot, lambda: app.storage_generation > generation and not app.storage_measuring)
            self.assertEqual(app.storage_node.status, 'measured', app.storage_node.issues)
            self.assertEqual(self.plan['config']['storage_max_files'], original_budget)
            self.assertFalse(app.query('#storage-budget'))
            await pilot.resize_terminal(90, 30)
            self.assertEqual(app.query_one('#tabs', TabbedContent).active, 'storage')

    async def test_background_discovery_streams_rows_and_cancels_without_freezing_tabs(self):
        template = self.plan
        class SlowScanner:
            def __init__(self, config, state, progress, cancel):
                self.progress, self.cancel = progress, cancel
            def run(self):
                self.progress('candidate', template['candidates'][0])
                while not self.cancel.wait(.03):
                    pass
                plan = dict(template, cancelled=True)
                plan['candidates'] = [dict(template['candidates'][0], eligible=False, blockers=['cancelled'])]
                return plan
        app = MacTrimApp(state=self.state, config=self.config, storage_root=self.data, scanner_factory=SlowScanner)
        async with app.run_test(size=(120,38)) as pilot:
            await self.wait_for(pilot, lambda: len(app.items) > 0)
            self.assertTrue(app.scanning)
            self.assertIsNone(app.plan)
            app.query_one('#tabs', TabbedContent).active = 'storage'
            await pilot.pause(.1)
            self.assertEqual(app.query_one('#tabs', TabbedContent).active, 'storage')
            app.scan_cancel.set()
            await self.wait_for(pilot, lambda: not app.scanning)
            self.assertTrue(app.plan['cancelled'])
            self.assertEqual(app.selected, set())
