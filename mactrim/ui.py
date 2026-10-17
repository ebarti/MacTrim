"""Native Textual widgets; all filesystem/process work runs in thread workers."""
from collections import Counter
from datetime import datetime
from pathlib import Path
import threading
import time

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.coordinate import Coordinate
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (Button, DataTable, Footer, Header, Input, Label,
                             OptionList, ProgressBar, Select, Static,
                             TabbedContent, TabPane)
from textual.widgets.option_list import Option

from .config import defaults
from .executor import Executor, selection
from .measurement import capacities
from .storage import page, page_offset, directory_page, storage_order, accounting, PAGE_SIZE, find_directory, StorageNode
from .regions import Cancelled
from .incremental import inventory
from .history import History
from .safety import SafetyError, canonical, clean, within
from .scanner import Scanner
from .tui import details, human

def signed_size(value):
    return ('−' if value < 0 else '+') + human(abs(value))


def index_save_status(node):
    saved = getattr(node, 'refresh', {}).get('cache')
    if not saved:
        return 'Index save status unavailable'
    if not saved.get('stored'):
        return 'INDEX NOT SAVED · ' + saved.get('reason', 'Save failed')
    if not saved.get('complete_index'):
        return 'TOTALS SAVED ONLY · Directory details exceeded retention limits; full scan required'
    if saved.get('reusable'):
        return 'INDEX SAVED · Incremental refresh available'
    return 'OBSERVATION SAVED · Full reconciliation required before reuse'


def highlighted_path(table):
    if table.row_count:
        return str(table.coordinate_to_cell_key(Coordinate(table.cursor_row, 0)).row_key.value)
    return None


def highlight_chart(chart, path):
    # Synchronizing a widget is presentation, not another navigation event.
    with chart.prevent(OptionList.OptionHighlighted):
        chart.highlighted = next((index for index, option in enumerate(chart.options) if option.id == path), None)


def current_chart_event(event):
    chart = event.control
    return chart.highlighted is not None and chart.get_option_at_index(chart.highlighted) is event.option


PALETTE = ('#67e8f9', '#a78bfa', '#fbbf24', '#34d399', '#fb7185', '#93c5fd')
STATUS_COLOR = {'measured': '#34d399', 'partial': '#fbbf24', 'denied': '#fb7185',
                'skipped': '#94a3b8', 'unknown': '#94a3b8', 'cancelled': '#fbbf24', 'scanning': '#67e8f9',
                'deferred': '#93c5fd'}


def storage_size(node, metric):
    if node.status in {'deferred', 'unknown'}:
        return 'Not measured'
    if node.status == 'scanning' and not getattr(node, metric):
        return 'Measuring…'
    return ('≥ ' if node.status in {'partial', 'denied', 'cancelled', 'scanning'} else '') + human(getattr(node, metric))


class Approval(ModalScreen):
    BINDINGS = [('escape', 'cancel', 'Cancel')]
    CSS = '''
    Approval { align: center middle; background: $background 75%; }
    #approval-dialog { width: 85%; max-width: 110; height: 80%; border: thick $warning; padding: 1 2; background: $surface; }
    #approval-items { height: 1fr; }
    #approval-buttons { height: 3; }
    #approval-error { height: 2; color: $error; }
    '''

    def __init__(self, phrase, items):
        super().__init__()
        self.phrase, self.items = phrase, items

    def compose(self):
        with Vertical(id='approval-dialog'):
            yield Label('Review exact quarantine selection', classes='title')
            yield Static('Quarantine moves data on the same volume and frees 0 bytes. Fresh safety validation runs again before mutation.')
            with VerticalScroll(id='approval-items'):
                for item in self.items:
                    yield Static(Text('\n'.join(details(item))))
            yield Static(Text('Type exactly: ' + self.phrase, style='bold #fbbf24'))
            yield Input(placeholder='Exact approval phrase', id='approval-input')
            yield Static('', id='approval-error')
            with Horizontal(id='approval-buttons'):
                yield Button('Cancel', id='approval-cancel')
                yield Button('Quarantine', variant='warning', id='approval-confirm')

    def on_mount(self):
        self.query_one('#approval-input', Input).focus()

    def action_cancel(self):
        self.dismiss(None)

    @on(Button.Pressed)
    def buttons(self, event):
        if event.button.id == 'approval-cancel':
            self.action_cancel()
        elif event.button.id == 'approval-confirm':
            self.confirm()

    @on(Input.Submitted)
    def submitted(self):
        self.confirm()

    def confirm(self):
        value = self.query_one('#approval-input', Input).value
        if value != self.phrase:
            self.query_one('#approval-error', Static).update('Exact phrase required; no items moved.')
        else:
            self.dismiss(value)


class Coverage(ModalScreen):
    BINDINGS = [Binding('escape', 'close', 'Close', priority=True)]
    CSS = '''
    Coverage { align: center middle; background: $background 75%; }
    #coverage-dialog { width: 90%; max-width: 120; height: 85%; border: thick $warning; padding: 1 2; background: $surface; }
    #coverage-reasons { height: 1fr; }
    '''

    def __init__(self, report):
        super().__init__()
        self.report = report

    def compose(self):
        with Vertical(id='coverage-dialog'):
            yield Label('Storage coverage · ' + ('COMPLETE' if self.report['complete'] else 'INCOMPLETE'))
            yield Static(Text(clean(self.report['scope'])))
            with VerticalScroll(id='coverage-reasons'):
                yield Static(self.report['note'])
                for category, label in [('permissions', 'Access blocked'), ('changes', 'Changed during measurement'),
                                        ('tracking', 'Change tracking uncertain'), ('other', 'Other incomplete scopes'),
                                        ('deferred', 'Legacy unmeasured folders')]:
                    count = self.report['counts'].get(category, 0)
                    if count:
                        yield Static(Text('\n%s: %s scopes' % (label, count), style='bold #fbbf24'))
                        for row in self.report['examples'][category]:
                            yield Static(Text('%s\n%s' % (clean(row['path']), clean(row['reason']))))
                        omitted = count - len(self.report['examples'][category])
                        if omitted:
                            yield Static('%s further scopes; directory details retain their individual reasons.' % omitted)
                if self.report['counts']['permissions']:
                    yield Static('\nFor protected personal folders: System Settings → Privacy & Security → Full Disk Access for the app that launches MacTrim. Unix permission failures may need a separate read-only privileged scan. A sudo password does not grant macOS privacy access.')
            yield Button('Close', id='coverage-close', variant='primary')

    def action_close(self):
        self.dismiss(None)

    @on(Button.Pressed)
    def close_button(self, event):
        if event.button.id == 'coverage-close':
            self.action_close()


class CancelScan(ModalScreen):
    BINDINGS = [Binding('y', 'confirm', 'Yes', priority=True),
                Binding('n', 'keep_running', 'No', priority=True),
                Binding('escape', 'keep_running', 'Keep running', priority=True)]
    CSS = '''
    CancelScan { align: center middle; background: $background 75%; }
    #cancel-dialog { width: 72; height: auto; border: thick $warning; padding: 1 2; background: $surface; }
    #cancel-buttons { height: 3; margin-top: 1; }
    #cancel-buttons Button { margin-right: 2; }
    '''

    def __init__(self, scope, path=None):
        super().__init__()
        self.scope, self.path = scope, path

    def compose(self):
        with Vertical(id='cancel-dialog'):
            yield Label('Cancel the %s scan? [y/n]' % self.scope.title(), classes='title')
            if self.path:
                yield Static(Text(clean(self.path)))
            yield Static('This stops only the %s scan. Other background scans keep running.' % self.scope.title())
            if self.scope == 'storage':
                yield Static('Unfinished progress is not saved. The previous saved index is preserved.')
            with Horizontal(id='cancel-buttons'):
                yield Button('No · keep running', id='cancel-no', variant='primary')
                yield Button('Yes · cancel scan', id='cancel-yes', variant='warning')

    def on_mount(self):
        self.query_one('#cancel-no', Button).focus()

    def action_confirm(self):
        self.dismiss(True)

    def action_keep_running(self):
        self.dismiss(False)

    @on(Button.Pressed)
    def buttons(self, event):
        event.stop()
        if event.button.id == 'cancel-yes':
            self.action_confirm()
        elif event.button.id == 'cancel-no':
            self.action_keep_running()


class MacTrimApp(App):
    TITLE = 'MacTrim'
    SUB_TITLE = 'Evidence-led cleanup · storage explorer'
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [('q', 'quit', 'Quit'), ('space', 'toggle', 'Select'),
                ('v', 'validate', 'Validate'), ('a', 'quarantine', 'Quarantine'),
                ('r', 'refresh', 'Refresh'), ('ctrl+x', 'request_cancel', 'Cancel scan')]
    CSS = '''
    Screen { background: #0b1120; color: #e2e8f0; }
    Header { background: #172554; color: #67e8f9; }
    Footer { background: #172554; }
    .title { color: #67e8f9; text-style: bold; }
    .toolbar { height: 3; margin-bottom: 1; }
    .toolbar Button { min-width: 10; margin-right: 1; }
    .toolbar Select { width: 18; margin-right: 1; }
    #search { width: 1fr; }
    #cleanup-summary, #storage-summary { height: auto; min-height: 3; max-height: 7; color: #a5b4fc; }
    #categories { height: auto; max-height: 3; color: #67e8f9; }
    #cleanup-body { height: 1fr; }
    #cleanup-table { width: 3fr; height: 1fr; border: round #334155; }
    #detail-scroll { width: 2fr; height: 1fr; border: round #334155; padding: 0 1; }
    #selected-summary { height: 2; color: #34d399; }
    #scan-progress { height: 1; }
    #cleanup-status { height: 3; color: #fbbf24; }
    #breadcrumbs { height: 2; color: #67e8f9; }
    #capacity { height: auto; max-height: 4; color: #a5b4fc; }
    #storage-body { height: 1fr; }
    #chart { width: 2fr; height: 1fr; border: round #334155; padding: 0 1; }
    #storage-table { width: 3fr; height: 1fr; border: round #334155; }
    #storage-detail { height: 4; color: #94a3b8; }
    #storage-status { height: 2; color: #fbbf24; }
    #history-summary { height: 4; color: #a5b4fc; }
    #history-body { height: 1fr; }
    #history-chart { width: 2fr; border: round #334155; }
    #history-table { width: 3fr; border: round #334155; }
    #history-detail { height: 5; color: #94a3b8; }
    #history-status { height: 3; color: #fbbf24; }
    #history-before, #history-after { width: 1fr; }
    
    TabPane { padding: 1; }
    '''

    def __init__(self, plan=None, state=None, config=None, storage_root='/', output=None,
                 initial_tab='cleanup', initial_full=False, scanner_factory=Scanner, executor_factory=Executor):
        super().__init__()
        self.plan, self.state = plan, state
        self.config = dict(defaults(), **(config or (plan['config'] if plan else {})))
        self.output, self.initial_tab, self.initial_full = output, initial_tab, initial_full
        self.scanner_factory, self.executor_factory = scanner_factory, executor_factory
        self.items = list(plan['candidates']) if plan else []
        self.selected, self.completed = set(), set()
        self.scanning = self.busy = False
        self.scan_cancel, self.storage_cancel = threading.Event(), threading.Event()
        self.storage_path = str(canonical(storage_root))
        self.storage_node = None
        self.storage_nodes = []
        self.storage_generation = 0
        self.storage_metric = 'allocated'
        self.storage_sort = 'size'
        self.storage_offset = 0
        self.storage_page_rows = []
        self.storage_inventory = None
        self.storage_progress = None
        self.storage_scan_path = self.storage_path
        self.storage_details = {}
        self.storage_has_more = False
        self.storage_page_cancel = threading.Event()
        self.storage_page_generation = 0
        self.storage_page_loading = False
        self.storage_page_issue = None
        self.storage_rendered_view = None
        self.storage_page_user_selected = False
        self.render_dirty = False
        self.capacity_rows = []
        self.storage_measuring = False
        self.history_result = None
        self.history_rows = []
        self.history_catalog = None
        self.history_earlier = self.history_later = None
        self.history_metric = 'allocated'
        self.history_sort = 'growth'
        self.history_choices_ready = False
        self.history_generation = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial=self.initial_tab, id='tabs'):
            with TabPane('Cleanup', id='cleanup'):
                yield Static('Nothing selected. Discovery is read-only; mutation requires complete evidence and exact approval.', id='cleanup-summary')
                yield Static('Categories waiting for bounded discovery…', id='categories')
                with Horizontal(classes='toolbar'):
                    yield Input(placeholder='Search path, category or owner', id='search')
                    yield Select([('All statuses', 'all'), ('Actionable', 'ready'), ('Reports', 'report')], value='all', allow_blank=False, id='filter')
                    yield Select([('Size ↓', 'size'), ('Path A–Z', 'path'), ('Category', 'kind')], value='size', allow_blank=False, id='sort')
                with Horizontal(id='cleanup-body'):
                    yield DataTable(id='cleanup-table', cursor_type='row', zebra_stripes=True)
                    with VerticalScroll(id='detail-scroll'):
                        yield Static('Highlight a row to inspect ownership, evidence and blockers.', id='details')
                yield Static('Selected 0 · 0 B estimate · quarantine frees 0 bytes', id='selected-summary')
                yield ProgressBar(total=None, show_eta=False, id='scan-progress')
                yield Static('Ready', id='cleanup-status')
                with Horizontal(classes='toolbar'):
                    yield Button('Rescan', id='rescan', variant='primary')
                    yield Button('Cancel', id='cancel-scan')
                    yield Button('Select', id='select-item')
                    yield Button('Validate', id='validate')
                    yield Button('Quarantine', id='quarantine', variant='warning')
            with TabPane('Storage', id='storage'):
                yield Static(Text(self.storage_path), id='breadcrumbs')
                yield Static('Filesystem capacity loading…', id='capacity')
                with Horizontal(classes='toolbar'):
                    yield Button('Root /', id='root')
                    yield Button('Parent ↑', id='parent')
                    yield Button('Refresh', id='storage-refresh', variant='primary')
                    yield Button('Cancel', id='cancel-storage')
                    yield Select([('Allocated', 'allocated'), ('Logical', 'logical')], value='allocated', allow_blank=False, id='metric')
                    yield Select([('Size ↓', 'size'), ('Name A–Z', 'name')], value='size', allow_blank=False, id='storage-sort')
                with Horizontal(classes='toolbar'):
                    yield Button('Full rescan', id='storage-full')
                    yield Button('Clear cache', id='storage-clear')
                    yield Button('Previous page', id='storage-prev')
                    yield Button('Next page', id='storage-next')
                    yield Button('Coverage', id='storage-coverage')
                yield Static('Metadata only · estimates are lower bounds when incomplete · Enter drills into a directory', id='storage-summary')
                with Horizontal(id='storage-body'):
                    yield OptionList(id='chart')
                    yield DataTable(id='storage-table', cursor_type='row', zebra_stripes=True)
                yield Static('The graph and list share the same measured nodes. Protected/system data stays read-only.', id='storage-detail')
                yield Static('Waiting for measurement', id='storage-status')
            with TabPane('History / Growth', id='history'):
                yield Static('Directory baselines reveal changes between comparable observations.', id='history-summary')
                with Horizontal(classes='toolbar'):
                    yield Button('Refresh', id='history-refresh', variant='primary')
                    yield Button('Capture current', id='history-capture')
                    yield Select([('Previous compatible', 'previous')], value='previous', allow_blank=False, id='history-before')
                    yield Select([('Latest observation', 'latest')], value='latest', allow_blank=False, id='history-after')
                with Horizontal(classes='toolbar'):
                    yield Select([('Allocated', 'allocated'), ('Logical', 'logical')], value='allocated', allow_blank=False, id='history-metric')
                    yield Select([('Growth ↓', 'growth'), ('Shrinkage ↓', 'shrink'), ('Path A–Z', 'path')], value='growth', allow_blank=False, id='history-sort')
                with Horizontal(id='history-body'):
                    yield OptionList(id='history-chart')
                    yield DataTable(id='history-table', cursor_type='row', zebra_stripes=True)
                yield Static('Enter opens a directory in Storage. Parent/child deltas overlap; never sum them. Recent activity bytes are clues, not growth.', id='history-detail')
                yield Static('History loading…', id='history-status')
        yield Footer()

    def query_main(self, selector, expect_type=None):
        # Background workers update the main view even while a modal is active.
        return self.screen_stack[0].query_one(selector, expect_type)

    def on_mount(self):
        self.query_main('#cleanup-table', DataTable).add_columns('Select', 'Status', 'Category', 'Allocated', 'Path')
        self.query_main('#storage-table', DataTable).add_columns('Status', 'Size', 'Directory / file')
        self.query_main('#history-table', DataTable).add_columns('Status', 'Change', '%', 'Directory')
        self.set_interval(.15, self.flush_rows)
        self.refresh_cleanup()
        if self.plan is None and self.state is not None and self.initial_tab == 'cleanup':
            self.start_scan()
        self.start_storage(self.storage_path, full=self.initial_full)
        self.load_history()

    def on_unmount(self):
        self.storage_page_cancel.set()
        self.scan_cancel.set()
        self.storage_cancel.set()

    def message(self, value):
        self.query_main('#cleanup-status', Static).update(Text(clean(value)))

    def flush_rows(self):
        if self.render_dirty:
            self.render_dirty = False
            self.refresh_cleanup()

    def visible_items(self):
        query = self.query_main('#search', Input).value.casefold()
        mode = self.query_main('#filter', Select).value
        sort = self.query_main('#sort', Select).value
        rows = [item for item in self.items if item['id'] not in self.completed and
                (mode == 'all' or item['eligible'] == (mode == 'ready')) and
                (not query or query in (item['path'] + ' ' + item['kind'] + ' ' + str(item['context'].get('bundle_id', ''))).casefold())]
        return sorted(rows, key=(lambda item: (-item['fingerprint']['allocated'], item['path'])) if sort == 'size' else lambda item: (item[sort], item['path']))

    def refresh_cleanup(self):
        table = self.query_main('#cleanup-table', DataTable)
        old_key = self.highlighted_cleanup()
        old_index = table.cursor_row
        table.clear()
        rows = self.visible_items()
        for item in rows:
            ready = item['eligible']
            table.add_row('✓' if item['id'] in self.selected else '□' if ready else '—',
                          Text('READY' if ready else 'REVIEW', style='#34d399' if ready else '#fbbf24'),
                          Text(clean(item['kind'])), human(item['fingerprint']['allocated']),
                          Text(clean(item['path'])), key=item['id'])
        if rows:
            index = next((i for i, item in enumerate(rows) if item['id'] == old_key), min(old_index, len(rows) - 1))
            table.move_cursor(row=index)
            self.show_cleanup_detail(rows[index]['id'])
        counts = Counter(item['kind'] for item in self.items)
        groups = {'repositories': 0, 'worktrees': 0, 'caches': 0, 'apps': 0, 'duplicates': 0, 'system': 0}
        for kind, count in counts.items():
            category = 'worktrees' if kind == 'git-worktree' else 'duplicates' if kind == 'duplicate' else 'repositories' if kind in {'repo-artifact', 'unique-artifact'} else 'system' if kind == 'macos-managed' else 'caches' if kind in {'user-cache', 'xcode-cache', 'app-cache'} else 'apps'
            groups[category] += count
        self.query_main('#categories', Static).update(Text('  ·  '.join('%s %s' % (kind, count) for kind, count in groups.items())))
        selected = [item for item in self.items if item['id'] in self.selected]
        size = sum(item['fingerprint']['allocated'] for item in selected)
        self.query_main('#selected-summary', Static).update('Selected %s · %s allocated estimate · quarantine frees 0 bytes' % (len(selected), human(size)))
        for identifier in ('validate', 'quarantine', 'select-item'):
            self.query_main('#' + identifier, Button).disabled = self.scanning or self.busy or self.plan is None
        self.query_main('#rescan', Button).disabled = self.scanning or self.busy

    def highlighted_cleanup(self):
        table = self.query_main('#cleanup-table', DataTable)
        if table.row_count:
            return str(table.coordinate_to_cell_key(Coordinate(table.cursor_row, 0)).row_key.value)
        return None

    def show_cleanup_detail(self, identifier):
        item = next((item for item in self.items if item['id'] == identifier), None)
        if item:
            self.query_main('#details', Static).update(Text('\n'.join(details(item))))

    @on(DataTable.RowHighlighted, '#cleanup-table')
    def cleanup_highlight(self, event):
        self.show_cleanup_detail(str(event.row_key.value))

    @on(Input.Changed, '#search')
    @on(Select.Changed, '#filter')
    @on(Select.Changed, '#sort')
    def cleanup_filter(self):
        if self.is_mounted:
            self.refresh_cleanup()

    def action_toggle(self):
        if self.query_main('#tabs', TabbedContent).active != 'cleanup' or self.scanning or self.busy or self.plan is None:
            return
        identifier = self.highlighted_cleanup()
        if identifier is None:
            return
        item = next(item for item in self.items if item['id'] == identifier)
        try:
            if identifier in self.selected:
                self.selected.remove(identifier)
            else:
                selection(self.plan, sorted(self.selected | {identifier}))
                self.selected.add(identifier)
            self.refresh_cleanup()
        except SafetyError as exc:
            self.message('Blocked: ' + clean(exc))

    def start_scan(self):
        if self.scanning or self.busy or self.state is None:
            return
        self.scan_cancel = threading.Event()
        self.scanning = True
        self.plan = None
        self.items = []
        self.selected.clear()
        self.completed.clear()
        self.query_main('#scan-progress', ProgressBar).update(total=None)
        self.message('Discovering current-user activity and configured scopes… navigation remains available')
        self.refresh_cleanup()
        self.scan_worker(self.scan_cancel)

    @work(thread=True, group='cleanup', exclusive=True)
    def scan_worker(self, cancel):
        try:
            def progress(kind, payload):
                self.call_from_thread(self.scan_event, kind, payload)
            plan = self.scanner_factory(self.config, self.state, progress=progress, cancel=cancel).run()
            if self.output:
                with self.state.lock():
                    from .cli import export
                    export(self.output, self.state.sign(plan))
            self.call_from_thread(self.scan_done, plan, None)
        except Exception as exc:
            self.call_from_thread(self.scan_done, None, clean(exc))

    def scan_event(self, kind, payload):
        if kind == 'candidate':
            self.items.append(payload)
            self.render_dirty = True
        else:
            self.message('Scanning %s: %s · partial results %s' % (payload['category'], clean(payload['root']), len(self.items)))

    def scan_done(self, plan, error):
        self.scanning = False
        if plan is not None:
            self.plan, self.items = plan, list(plan['candidates'])
            activity = 'complete for current UID' if plan['activity']['complete'] else 'INCOMPLETE — actions blocked'
            partial = sum(row.get('status') in {'partial', 'cancelled'} for row in plan['coverage'])
            self.query_main('#cleanup-summary', Static).update(Text('%s candidates · %s partial scopes · activity %s\n%s logical / %s allocated estimate; APFS reclamation can differ' % (len(self.items), partial, activity, human(plan['totals']['logical']), human(plan['totals']['allocated']))))
            issues = plan['activity']['issues'] + plan['issues']
            self.message(('Discovery cancelled; rescan before actions. ' if plan.get('cancelled') else 'Discovery finished. ') + ('; '.join(issues[:4]) if issues else 'Review evidence and select explicitly.'))
        else:
            self.message('Discovery failed: ' + str(error))
        self.query_main('#scan-progress', ProgressBar).update(total=1, progress=1)
        self.refresh_cleanup()

    def action_validate(self):
        self.validate_selection(False)

    def action_quarantine(self):
        self.validate_selection(True)

    def validate_selection(self, apply):
        if self.scanning or self.busy or self.plan is None:
            return
        try:
            items = selection(self.plan, sorted(self.selected))
        except SafetyError as exc:
            self.message('Blocked: ' + clean(exc))
            return
        self.busy = True
        self.refresh_cleanup()
        self.message('Fresh validation is running…')
        self.validate_worker(self.plan, [item['id'] for item in items], items, apply)

    @work(thread=True, group='mutation', exclusive=True)
    def validate_worker(self, plan, ids, items, apply):
        try:
            result = self.executor_factory(self.state).dry_run(plan, ids)
            self.call_from_thread(self.validation_done, plan, ids, items, apply, result['approval'], None)
        except Exception as exc:
            self.call_from_thread(self.validation_done, plan, ids, items, apply, None, clean(exc))

    def validation_done(self, plan, ids, items, apply, phrase, error):
        if error:
            self.busy = False
            self.message('Blocked: ' + error)
            self.refresh_cleanup()
        elif apply:
            def approved(value):
                if value is None:
                    self.busy = False
                    self.message('Approval cancelled; no items moved')
                    self.refresh_cleanup()
                else:
                    self.apply_worker(plan, ids, value)
            self.push_screen(Approval(phrase, items), approved)
        else:
            self.busy = False
            self.message('Validated. Exact approval: ' + phrase)
            self.refresh_cleanup()

    @work(thread=True, group='mutation', exclusive=True)
    def apply_worker(self, plan, ids, phrase):
        try:
            result = self.executor_factory(self.state).apply(plan, ids, phrase)
            self.call_from_thread(self.apply_done, result, None)
        except Exception as exc:
            self.call_from_thread(self.apply_done, None, clean(exc))

    def apply_done(self, result, error):
        self.busy = False
        if error:
            self.message('Blocked: ' + error)
        else:
            paths = {row['path'] for row in result['outcomes'] if row['status'] == 'quarantined'}
            self.completed.update(item['id'] for item in self.items if item['path'] in paths)
            self.selected.difference_update(self.completed)
            self.message('; '.join(row['status'] + ': ' + clean(row.get('reason', row['path'])) for row in result['outcomes']))
        self.refresh_cleanup()

    def start_storage(self, path, full=False, refresh=False):
        target = str(canonical(path))
        if not self.storage_measuring and (full or refresh) and self.storage_inventory is not None and target != self.storage_inventory.path and within(target, self.storage_inventory.path):
            self.start_details(target)
            return
        if not full and not refresh and (self.storage_measuring or (target != self.storage_path and self.storage_inventory is not None)):
            source = self.storage_progress if self.storage_measuring else self.storage_inventory
            if self.storage_measuring:
                remembered = find_directory(source, target) if source is not None else None
            else:
                remembered = self.observed_directory(target)
            if remembered is None and self.storage_measuring and self.storage_node is not None:
                remembered = find_directory(self.storage_node, target)
            if remembered is None and (not self.storage_measuring or not within(target, self.storage_scan_path)):
                remembered = self.observed_directory(target)
            if self.storage_measuring or remembered is not None:
                self.storage_path, self.storage_offset = target, 0
                self.storage_node = remembered or StorageNode(target, Path(target).name or '/', kind='directory', status='scanning')
                self.query_main('#breadcrumbs', Static).update(Text(target, style='bold #67e8f9'))
                if not self.storage_measuring:
                    self.load_storage_page()
                self.refresh_storage()
                self.query_main('#storage-status', Static).update(
                    'Browsing while scan continues at %s; waiting for observed directory details' % self.storage_scan_path if self.storage_measuring else
                    'Cached observation; Refresh verifies current filesystem events')
                if not self.storage_measuring and self.storage_node.details_deferred:
                    self.start_details(target)
                return
        self.storage_cancel.set()
        self.storage_cancel = threading.Event()
        self.storage_generation += 1
        self.storage_path = str(canonical(path))
        self.storage_scan_path = self.storage_path
        self.storage_progress = None
        self.storage_details.clear()
        self.storage_node = None
        self.storage_offset = 0
        self.storage_page_rows = []
        self.storage_measuring = True
        self.query_main('#breadcrumbs', Static).update(Text(self.storage_path, style='bold #67e8f9'))
        self.query_main('#storage-status', Static).update('Measuring metadata in background… totals are lower bounds')
        self.storage_worker(self.storage_path, self.storage_cancel, self.storage_generation, dict(self.config), full)

    def observed_directory(self, target):
        for root in sorted(self.storage_details.values(), key=lambda node: len(node.path), reverse=True):
            node = find_directory(root, target)
            if node is not None:
                return node
        return find_directory(self.storage_inventory, target) if self.storage_inventory is not None else None

    def start_details(self, target):
        self.storage_generation += 1
        self.storage_cancel = threading.Event()
        self.storage_path = self.storage_scan_path = target
        self.storage_measuring = True
        self.query_main('#storage-status', Static).update('Loading directory details; main index preserved')
        self.details_worker(target, self.storage_cancel, self.storage_generation, dict(self.config))

    @work(thread=True, group='storage-details', exclusive=True)
    def details_worker(self, path, cancel, generation, config):
        def progress(node, current):
            if not cancel.is_set():
                self.call_from_thread(self.storage_update, node, generation, False, True)
        progress.view = lambda: self.storage_path
        try:
            # Details are an independent observation, never a replacement for
            # the completed whole-scope index or its History baseline.
            node = inventory(path, None, config, cancel=cancel, progress=progress)
            self.call_from_thread(self.storage_update, node, generation, True, True)
        except Exception as exc:
            if self.is_running:
                self.call_from_thread(self.storage_error, generation, clean(exc))

    @work(thread=True, group='storage', exclusive=True)
    def storage_worker(self, path, cancel, generation, config, full=False):
        last, last_phase = [0.0], [None]
        def progress(node, child):
            now = time.monotonic()
            phase = getattr(node, 'progress', {}).get('phase')
            if (now - last[0] >= .15 or phase != last_phase[0]) and not cancel.is_set():
                last_phase[0] = phase
                last[0] = now
                self.call_from_thread(self.storage_update, node, generation, False)
        try:
            capacity = capacities('/')
            self.call_from_thread(self.capacity_update, capacity, generation)
            progress.view = lambda: self.storage_path
            node = inventory(path, self.state, config, cancel=cancel, progress=progress, full=full)
            self.call_from_thread(self.storage_update, node, generation, True)
            if self.state is not None and not cancel.is_set() and node.entries > 1:
                try:
                    result = History(self.state, config).capture(node, capacity, automatic=True)
                    self.call_from_thread(self.history_captured, result, None)
                except Exception as exc:
                    self.call_from_thread(self.history_captured, None, clean(exc))
        except Exception as exc:
            if self.is_running:
                self.call_from_thread(self.storage_error, generation, clean(exc))

    def capacity_update(self, rows, generation=None):
        if not self.is_running:
            return
        if generation is not None and generation != self.storage_generation:
            return
        self.capacity_rows = rows
        text = Text()
        for row in rows:
            if row.get('status') != 'measured':
                text.append('%s: %s\n' % (row['label'], row.get('issue', row.get('status'))))
            else:
                text.append('%s · used %s · available %s · total %s\n' % (row['label'], human(row['used']), human(row['available']), human(row['total'])))
        text.append('Filesystem capacity is separate from directory estimates; APFS volumes share capacity.', style='#94a3b8')
        self.query_main('#capacity', Static).update(text)

    def storage_error(self, generation, error):
        if self.is_running and generation == self.storage_generation:
            self.storage_measuring = False
            self.query_main('#storage-status', Static).update(Text('Measurement failed: ' + error))

    def storage_update(self, node, generation, done, detail=False):
        if not self.is_running or generation != self.storage_generation:
            return
        self.storage_progress = node
        selected = (getattr(node, 'view', None) if not done else find_directory(node, self.storage_path))
        if selected is not None and selected.path != self.storage_path:
            selected = None
        if selected is None and node.path == self.storage_path:
            selected = node
        if selected is None:
            selected = self.observed_directory(self.storage_path)
        self.storage_node = selected or StorageNode(self.storage_path, Path(self.storage_path).name or '/', kind='directory', status='scanning' if not done else 'unknown')
        if done:
            self.storage_measuring = False
            if detail:
                if node.status != 'cancelled':
                    self.storage_details[node.path] = node
            else:
                self.storage_inventory = node
            self.load_storage_page()
        self.refresh_storage()
        status = '%s · %s metadata visits · %s' % (node.status.upper(), getattr(node, 'counters', {}).get('visited', node.entries), '; '.join(node.issues[:2]) if done else ('%s · %s' % (getattr(node, 'progress', {}).get('phase', 'Measuring'), clean(getattr(node, 'progress', {}).get('path', node.path)))))
        if done and node.status == 'cancelled':
            status += ' · Storage stopped; Refresh starts another scan. Previous saved index preserved.'
        elif done:
            status = 'Scan finished (%s) · %s\n%s metadata visits · %s' % (node.status.upper(), 'Details loaded; main index preserved' if detail else index_save_status(node), getattr(node, 'counters', {}).get('visited', node.entries), '; '.join(node.issues[:2]))
            report = getattr(node, 'refresh', {}).get('coverage')
            if report and not report['complete']:
                status += ' · Coverage shows exact blockers'
        self.query_main('#storage-status', Static).update(Text(status, style=STATUS_COLOR.get(node.status, '#fbbf24')))
        if done and not detail and node.status != 'cancelled' and self.storage_node.details_deferred:
            self.start_details(self.storage_path)

    def refresh_storage(self, selected_path=None):
        if self.storage_node is None:
            return
        metric = self.storage_metric
        node = self.storage_node
        self.storage_nodes = (list(self.storage_page_rows) if not self.storage_measuring else
                              directory_page(node, metric=metric, order=self.storage_sort)[0])
        table = self.query_main('#storage-table', DataTable)
        rendering = (node.path, self.storage_offset, metric, self.storage_sort)
        changed_scope = self.storage_rendered_view != rendering
        old_index, old_path = (0, None) if changed_scope else (table.cursor_row, highlighted_path(table))
        old_path = selected_path or old_path
        self.storage_rendered_view = rendering
        chart = self.query_main('#chart', OptionList)
        with table.prevent(DataTable.RowHighlighted), chart.prevent(OptionList.OptionHighlighted):
            table.clear()
            chart.clear_options()
            root_accounting = accounting(node, self.capacity_rows)
            total = (root_accounting['filesystem_used_denominator'] if node.path == '/' and metric == 'allocated' else None) or getattr(node, metric)
            graph_rows = directory_page(node, limit=15, metric=metric)[0]
            for index, child in enumerate(self.storage_nodes):
                table.add_row(Text(child.status.upper() + (' · LAZY' if getattr(child, 'details_deferred', False) else ''), style=STATUS_COLOR.get(child.status, '#94a3b8')), storage_size(child, metric), Text(clean(child.name) + ('/' if child.kind == 'directory' else '')), key=child.path)
            for index, child in enumerate(graph_rows):
                fraction = getattr(child, metric) / total if total else 0
                bar = '━' * round(fraction * 24)
                text = Text('%2d  ' % (index + 1))
                text.append(bar.ljust(24), style=PALETTE[index % len(PALETTE)])
                percent = '    —' if child.status in {'deferred', 'unknown'} else '%5.1f%%' % (fraction * 100)
                text.append(' %s  %s\n    %s · %s' % (percent, clean(child.name), storage_size(child, metric), child.status.upper()))
                chart.add_option(Option(text, id=child.path))
            if self.storage_nodes:
                index = next((i for i, row in enumerate(self.storage_nodes) if row.path == old_path), min(old_index, len(self.storage_nodes) - 1))
                table.move_cursor(row=index)
                highlight_chart(chart, self.storage_nodes[index].path)
            if changed_scope and selected_path is None:
                table.scroll_home(animate=False, immediate=True)
                chart.scroll_home(animate=False, immediate=True)
        if self.storage_nodes:
            self.storage_selected(highlighted_path(table))
        refresh = getattr(node, 'refresh', {})
        cache = refresh.get('cache', {})
        refresh_note = '%s · visited %s / reused %s · %s' % (refresh.get('mode', 'scanning').upper(), getattr(node, 'counters', {}).get('visited', refresh.get('visited', 0)), getattr(node, 'counters', {}).get('reused', refresh.get('reused_entries', 0)), refresh.get('reason', ''))
        if not refresh and not self.storage_measuring:
            refresh_note = 'CACHED · directory observation; Refresh verifies current changes'
        if refresh.get('last_verified'):
            refresh_note += ' · verified ' + datetime.fromtimestamp(refresh['last_verified']).strftime('%b %d %H:%M:%S')
        if cache:
            refresh_note += ' · ' + index_save_status(node)
            if cache.get('directory_count') is not None:
                refresh_note += ' · %s directories retained' % cache['directory_count'] if cache.get('stored') else ' · %s directories measured' % cache['directory_count']
            if 'limit_bytes' in cache:
                refresh_note += ' · cache %s / %s' % (human(cache.get('allocated_bytes', 0)), human(cache['limit_bytes']) if cache['limit_bytes'] is not None else 'automatic sizing')
        if refresh.get('warnings'):
            refresh_note += ' · ' + '; '.join(refresh['warnings'][:2])
        diagnostic = refresh.get('events', {})
        if diagnostic.get('mode') == 'journal':
            refresh_note += '\nJournal: %s reads · %s recovered replays · checkpoint %s' % (
                diagnostic.get('replay_attempts', 0), diagnostic.get('recovered_replays', 0),
                diagnostic.get('checkpoint', 0))
            if diagnostic.get('source') == 'device-journal':
                refresh_note += ' · device %s · %s mount changes' % (diagnostic.get('device'), diagnostic.get('mount_signals', 0))
        if diagnostic.get('receiver_pid'):
            refresh_note += '\nReceiver: %s callbacks · %s drop signals · %s pending regions · %s broader invalidations · slowest callback %.2f ms' % (
                diagnostic.get('callbacks', 0), diagnostic.get('drop_signals', 0),
                diagnostic.get('pending_regions', 0),
                diagnostic.get('coarsened_batches', 0) + diagnostic.get('coarsened_regions', 0),
                diagnostic.get('callback_max_ms', 0))
        difference = accounting(node, self.capacity_rows)['difference'] if node.path == '/' else None
        note = (' · signed filesystem difference %s (APFS/excluded/inaccessible)' % signed_size(difference)) if difference is not None else ''
        if self.storage_measuring:
            discovery = getattr(node, 'progress', {})
            if discovery.get('traversal') == 'levels':
                refresh_note += ' · discovering level %s (scan root = 0)' % discovery.get('depth', 0)
            elif discovery.get('traversal') == 'native':
                refresh_note += ' · native size scan; completed folder totals stream as measured'
            refresh_note += ' · live rows: largest %s observed directories; totals include all observations' % PAGE_SIZE
            refresh_note += ' · scan root: ' + self.storage_scan_path
        if self.storage_page_loading and not self.storage_measuring:
            refresh_note += ' · loading current entries'
        if self.storage_page_issue:
            refresh_note += ' · ' + self.storage_page_issue
        if getattr(node, 'details_deferred', False):
            refresh_note += ' · recursive size included; internal browsing details load when opened'
        lifecycle = ('CANCELLING; observed lower bounds' if self.storage_cancel.is_set() else 'SCANNING; observed lower bounds') if self.storage_measuring else node.status.upper()
        if self.storage_measuring and getattr(node, 'progress', {}).get('scope_finished') and not self.storage_cancel.is_set():
            lifecycle = node.status.upper() + '; background scan continues'
        self.query_main('#storage-summary', Static).update(Text('%s %s · %s · page %s%s\nGraph: top 15 directories / filesystem used at root (allocated), otherwise observed scope bytes. Recursive sizes include collapsed folders. Open a lazy folder for internal browsing details.' % (storage_size(node, metric), metric, lifecycle, self.storage_offset // PAGE_SIZE + 1, note) + '\n' + refresh_note))

    @work(thread=True, group='storage-cache', exclusive=True)
    def clear_storage_cache(self):
        try:
            from .storage_cache import Cache
            result = Cache(self.state, self.config['storage_cache']).clear()
            self.call_from_thread(self.query_main('#storage-status', Static).update, Text('Owned cache cleared: ' + str(result)))
        except Exception as exc:
            self.call_from_thread(self.query_main('#storage-status', Static).update, Text('Cache preserved: ' + clean(exc)))

    def load_storage_page(self, target=None):
        if self.storage_node is None:
            return
        self.storage_page_cancel.set()
        self.storage_page_cancel = threading.Event()
        self.storage_page_generation += 1
        self.storage_page_issue = None
        self.storage_page_user_selected = False
        node = self.storage_node
        if target:
            selected = next((child for child in node.children if child.path == target), None)
            if selected:
                key = storage_order(self.storage_metric, self.storage_sort)
                rank = sum(key(child) < key(selected) for child in node.children)
                self.storage_offset = rank // PAGE_SIZE * PAGE_SIZE
        self.storage_page_rows, self.storage_has_more = directory_page(
            node, self.storage_offset, metric=self.storage_metric, order=self.storage_sort)
        self.storage_page_loading = not node.details_deferred
        if self.storage_page_loading:
            self.storage_page_worker(node, self.storage_offset, self.storage_metric, self.storage_sort,
                                     self.storage_page_cancel, self.storage_page_generation,
                                     self.storage_generation, target)

    @work(thread=True, group='storage-page', exclusive=True)
    def storage_page_worker(self, node, offset, metric, order, cancel, generation, scan_generation, target):
        try:
            if target:
                offset = page_offset(node, target, metric, order, cancel)
            rows, more = page(node, offset, metric=metric, order=order, cancel=cancel)
            issue = None
        except Cancelled:
            return
        except (OSError, SafetyError) as exc:
            rows, more = directory_page(node, offset, metric=metric, order=order)
            issue = 'Cached folders shown; current file listing unavailable: ' + clean(exc)
        if not cancel.is_set() and self.is_running:
            self.call_from_thread(self.storage_page_update, node.path, offset, rows, more, issue,
                                  generation, scan_generation, target)

    def storage_page_update(self, path, offset, rows, more, issue, generation, scan_generation, target=None):
        if (not self.is_running or generation != self.storage_page_generation or
                scan_generation != self.storage_generation or self.storage_measuring or path != self.storage_path):
            return
        self.storage_offset = offset
        self.storage_page_rows, self.storage_has_more = rows, more
        self.storage_page_loading = False
        self.storage_page_issue = issue
        selected = target or (rows[0].path if rows and not self.storage_page_user_selected else None)
        self.refresh_storage(selected_path=selected)

    @on(Select.Changed, '#metric')
    @on(Select.Changed, '#storage-sort')
    def storage_settings(self):
        self.storage_metric = self.query_main('#metric', Select).value
        self.storage_sort = self.query_main('#storage-sort', Select).value
        self.storage_offset = 0
        if self.storage_node is not None and not self.storage_measuring:
            self.load_storage_page()
        self.refresh_storage()

    def storage_selected(self, path):
        node = next((node for node in self.storage_nodes if node.path == path), None)
        if node is None and self.storage_node is not None:
            node = next((child for child in self.storage_node.children if child.path == path), None)
        if node:
            self.query_main('#storage-detail', Static).update(Text('%s\n%s logical · %s allocated · %s · %s\n%s' % (clean(node.path), storage_size(node, 'logical'), storage_size(node, 'allocated'), node.status.upper(), 'protected: read-only' if node.protected else 'read-only metadata', ('Recursive size included; internal browsing details load when opened. ' if getattr(node, 'details_deferred', False) else '') + ('; '.join(node.issues) or 'No content read'))))
        return node

    @on(DataTable.RowHighlighted, '#storage-table')
    def storage_highlight(self, event):
        path = str(event.row_key.value)
        if path != highlighted_path(event.control):
            return
        self.storage_page_user_selected = True
        self.storage_selected(path)
        highlight_chart(self.query_main('#chart', OptionList), path)

    @on(OptionList.OptionHighlighted, '#chart')
    def chart_highlight(self, event):
        if not current_chart_event(event):
            return
        path = event.option.id
        self.storage_page_user_selected = True
        node = self.storage_selected(path)
        if node:
            index = next((i for i, row in enumerate(self.storage_nodes) if row.path == path), None)
            if index is None:
                if not self.storage_measuring:
                    self.load_storage_page(target=path)
                    self.refresh_storage(selected_path=path)
                return
            table = self.query_main('#storage-table', DataTable)
            with table.prevent(DataTable.RowHighlighted):
                table.move_cursor(row=index)

    @on(DataTable.RowSelected, '#storage-table')
    def storage_enter(self, event):
        self.drill(str(event.row_key.value))

    @on(OptionList.OptionSelected, '#chart')
    def chart_enter(self, event):
        self.drill(event.option.id)

    def drill(self, path):
        node = self.storage_selected(path)
        if node and node.kind == 'directory' and node.status not in {'denied', 'skipped'}:
            if not isinstance(node, StorageNode) and self.storage_inventory is not None and within(path, self.storage_inventory.path):
                self.start_details(path)
            else:
                self.start_storage(path)

    def cancel_storage(self):
        self.storage_cancel.set()
        self.query_main('#storage-status', Static).update('Cancellation requested; waiting for the current operation to return…')
        self.refresh_storage()

    def request_scan_cancel(self, scope):
        if isinstance(self.screen, CancelScan):
            return
        running = self.storage_measuring if scope == 'storage' else self.scanning
        token = self.storage_cancel if scope == 'storage' else self.scan_cancel
        if not running or token.is_set():
            self.notify('No %s scan waiting for cancellation.' % scope.title())
            return
        def confirmed(answer):
            current = self.storage_cancel if scope == 'storage' else self.scan_cancel
            running = self.storage_measuring if scope == 'storage' else self.scanning
            if not answer or current is not token or not running:
                return
            if scope == 'storage':
                self.cancel_storage()
            else:
                token.set()
                self.message('Cleanup cancellation requested; Storage continues independently if running')
        self.push_screen(CancelScan(scope, self.storage_path if scope == 'storage' else None), confirmed)

    def action_request_cancel(self):
        scope = self.query_main('#tabs', TabbedContent).active
        if scope in {'storage', 'cleanup'}:
            self.request_scan_cancel(scope)
        else:
            self.notify('Choose Storage or Cleanup to cancel its scan with Ctrl+X.')

    def action_refresh(self):
        if self.query_main('#tabs', TabbedContent).active == 'storage':
            self.start_storage(self.storage_path, refresh=True)
        elif self.query_main('#tabs', TabbedContent).active == 'history':
            self.load_history()
        else:
            self.start_scan()

    @on(Button.Pressed)
    def buttons(self, event):
        identifier = event.button.id
        if identifier == 'rescan':
            self.start_scan()
        elif identifier == 'cancel-scan':
            self.request_scan_cancel('cleanup')
        elif identifier == 'select-item':
            self.action_toggle()
        elif identifier == 'validate':
            self.action_validate()
        elif identifier == 'quarantine':
            self.action_quarantine()
        elif identifier == 'root':
            self.start_storage('/')
        elif identifier == 'parent':
            self.start_storage(str(Path(self.storage_path).parent))
        elif identifier == 'storage-refresh':
            self.start_storage(self.storage_path, refresh=True)
        elif identifier == 'cancel-storage':
            self.request_scan_cancel('storage')
        elif identifier == 'storage-full':
            self.start_storage(self.storage_path, full=True)
        elif identifier == 'storage-coverage' and self.storage_node is not None and not self.storage_measuring:
            from .storage import coverage_report
            self.push_screen(Coverage(getattr(self.storage_node, 'refresh', {}).get('coverage') or coverage_report(self.storage_node)))
        elif identifier == 'storage-clear' and not self.storage_measuring and self.state is not None:
            self.clear_storage_cache()
        elif identifier in {'storage-prev', 'storage-next'} and not self.storage_measuring:
            if identifier == 'storage-prev':
                self.storage_offset = max(0, self.storage_offset - PAGE_SIZE)
            elif self.storage_has_more:
                self.storage_offset += PAGE_SIZE
            self.load_storage_page()
            self.refresh_storage()
        elif identifier == 'history-refresh':
            self.load_history()
        elif identifier == 'history-capture':
            self.capture_current()


    def load_history(self):
        if self.state is None:
            self.query_main('#history-status', Static).update('This session has no private state; use the installed CLI to enable local history.')
            return
        self.history_generation += 1
        self.history_worker(self.history_earlier, self.history_later, self.history_metric, self.history_generation)

    @work(thread=True, group='history', exclusive=True)
    def history_worker(self, earlier, later, metric, generation):
        try:
            history = History(self.state, self.config)
            catalog = history.list()
            comparison = history.compare(earlier, later, metric) if catalog['snapshots'] else {'rows': [], 'capacity': [], 'note': 'No baseline yet. A completed Storage measurement establishes a local baseline; another comparable observation is needed to measure growth.'}
            self.call_from_thread(self.history_loaded, catalog, comparison, None, generation)
        except Exception as exc:
            self.call_from_thread(self.history_loaded, None, None, clean(exc), generation)

    def history_loaded(self, catalog, result, error, generation):
        if generation != self.history_generation:
            return
        if error:
            self.query_main('#history-status', Static).update(Text('History unavailable: ' + error + ' · cleanup and browsing remain available'))
            return
        self.history_catalog, self.history_result = catalog, result
        self.history_choices_ready = False
        choices = [(datetime.fromtimestamp(row['created_at']).strftime('%b %d %H:%M') + ' ' + clean(row['scope'])[-30:], row['id']) for row in catalog['snapshots'] if not row['temporary']]
        before = self.query_main('#history-before', Select)
        after = self.query_main('#history-after', Select)
        before.set_options([('Previous compatible', 'previous')] + choices)
        after.set_options([('Latest observation', 'latest')] + choices)
        before.value = self.history_earlier or 'previous'
        after.value = self.history_later or 'latest'
        self.history_choices_ready = True
        self.refresh_history()

    def refresh_history(self):
        if self.history_result is None:
            return
        result, catalog = self.history_result, self.history_catalog
        key = (lambda row: (row['delta'] is None, -(row['delta'] or 0), row['path'])) if self.history_sort == 'growth' else (lambda row: (row['delta'] is None, row['delta'] or 0, row['path'])) if self.history_sort == 'shrink' else lambda row: row['path']
        self.history_rows = sorted(result.get('rows', []), key=key)
        table = self.query_main('#history-table', DataTable)
        old_index, old_path = table.cursor_row, highlighted_path(table)
        chart = self.query_main('#history-chart', OptionList)
        with table.prevent(DataTable.RowHighlighted), chart.prevent(OptionList.OptionHighlighted):
            table.clear()
            chart.clear_options()
            scale = max((abs(row['delta']) for row in self.history_rows if row['delta'] is not None), default=1) or 1
            for index, row in enumerate(self.history_rows):
                delta = row['delta']
                color = '#fbbf24' if delta is None else '#fb7185' if delta > 0 else '#34d399' if delta < 0 else '#94a3b8'
                change = 'unknown' if delta is None else ('+' if delta > 0 else '') + human(delta)
                percent = '—' if row['percent'] is None else '%+.1f%%' % row['percent']
                table.add_row(Text(row['status'], style=color), Text(change, style=color), percent, Text(clean(row['path'])), key=row['path'])
                if index < 15:
                    bar = '━' * round(abs(delta or 0) / scale * 24)
                    text = Text(bar.ljust(24) + ' ' + change + '\n' + clean(row['path']), style=color)
                    chart.add_option(Option(text, id=row['path']))
            if self.history_rows:
                index = next((i for i, row in enumerate(self.history_rows) if row['path'] == old_path), min(old_index, len(self.history_rows) - 1))
                table.move_cursor(row=index)
                highlight_chart(chart, self.history_rows[index]['path'])
        if self.history_rows:
            self.history_detail(highlighted_path(table))
        times = ''
        if result.get('earlier_at'):
            times = datetime.fromtimestamp(result['earlier_at']).strftime('%Y-%m-%d %H:%M') + ' → ' + datetime.fromtimestamp(result['later_at']).strftime('%Y-%m-%d %H:%M')
        capacity = ' · '.join(clean(row['label']) + ': used ' + ('+' if row['used_delta'] > 0 else '') + human(row['used_delta']) + (' (shared/alias; not additive)' if row['shared_observation_alias'] else '') for row in result.get('capacity', []))
        self.query_main('#history-summary', Static).update(Text('%s\n%s\nHistory %s / %s allocated · %s snapshots · %s directory estimates' % (times or 'First measured baseline / no comparable pair', capacity or 'Capacity trends require two observations; directory growth requires comparable measured baselines.', human(catalog['allocated_bytes']), human(catalog['limit_bytes']), len(catalog['snapshots']), self.history_metric)))
        self.query_main('#history-status', Static).update(Text(result.get('note', '') + (' · ' + '; '.join(catalog['issues'] + result.get('issues', [])) if catalog['issues'] or result.get('issues') else '')))

    @on(Select.Changed, '#history-before')
    @on(Select.Changed, '#history-after')
    @on(Select.Changed, '#history-metric')
    def history_selection(self):
        if not self.is_mounted or not self.history_choices_ready:
            return
        before = self.query_main('#history-before', Select).value
        after = self.query_main('#history-after', Select).value
        metric = self.query_main('#history-metric', Select).value
        values = (None if before == 'previous' else before, None if after == 'latest' else after, metric)
        if values != (self.history_earlier, self.history_later, self.history_metric):
            self.history_earlier, self.history_later, self.history_metric = values
            self.load_history()

    @on(Select.Changed, '#history-sort')
    def history_sort_changed(self):
        self.history_sort = self.query_main('#history-sort', Select).value
        self.refresh_history()

    def history_captured(self, result, error):
        if not self.is_running:
            return
        if error:
            self.query_main('#history-status', Static).update(Text('History capture unavailable: ' + error + ' · browser remains usable'))
        else:
            self.load_history()

    def capture_current(self):
        if self.storage_measuring or self.storage_node is None or self.state is None:
            self.query_main('#history-status', Static).update('Wait for a completed Storage measurement; capture does not run another scan.')
            return
        self.manual_capture_worker(self.storage_node, self.capacity_rows)

    @work(thread=True, group='history-capture', exclusive=True)
    def manual_capture_worker(self, node, capacity):
        try:
            result = History(self.state, self.config).capture(node, capacity)
            self.call_from_thread(self.history_captured, result, None)
        except Exception as exc:
            self.call_from_thread(self.history_captured, None, clean(exc))

    def history_detail(self, path):
        row = next((row for row in self.history_rows if row['path'] == path), None)
        if row:
            recent = row['recent']
            proven = row['status'] in {'comparable', 'new-directory', 'removed-directory'}
            before = human(row['before']) if proven and row['before'] is not None else 'unknown'
            after = human(row['after']) if proven and row['after'] is not None else 'unknown'
            if row['status'] == 'new-directory':
                before = '0 B (absent)'
            elif row['status'] == 'removed-directory':
                after = '0 B (absent)'
            overlap = ' · Included in parent totals' if row['overlaps_parent'] else ''
            self.query_main('#history-detail', Static).update(Text('%s\n%s · before %s · after %s%s\nCurrent recently modified allocated bytes: 7d %s / 30d %s; recently created 7d %s — activity clues, NOT measured growth.\nEnter opens this directory in Storage; missing/partial observations remain unknown.' % (clean(path), row['status'], before, after, overlap, human(recent.get('modified_7d', 0)), human(recent.get('modified_30d', 0)), human(recent.get('created_7d', 0)))))

    @on(DataTable.RowHighlighted, '#history-table')
    def history_highlight(self, event):
        path = str(event.row_key.value)
        if path != highlighted_path(event.control):
            return
        self.history_detail(path)
        highlight_chart(self.query_main('#history-chart', OptionList), path)

    @on(OptionList.OptionHighlighted, '#history-chart')
    def history_chart_highlight(self, event):
        if not current_chart_event(event):
            return
        path = event.option.id
        self.history_detail(path)
        index = next((i for i, row in enumerate(self.history_rows) if row['path'] == path), None)
        if index is not None:
            table = self.query_main('#history-table', DataTable)
            with table.prevent(DataTable.RowHighlighted):
                table.move_cursor(row=index)

    @on(DataTable.RowSelected, '#history-table')
    def history_enter(self, event):
        self.query_main('#tabs', TabbedContent).active = 'storage'
        self.start_storage(str(event.row_key.value))
        self.call_after_refresh(self.query_main('#storage-table', DataTable).focus)

    @on(OptionList.OptionSelected, '#history-chart')
    def history_chart_enter(self, event):
        self.query_main('#tabs', TabbedContent).active = 'storage'
        self.start_storage(event.option.id)
        self.call_after_refresh(self.query_main('#storage-table', DataTable).focus)
