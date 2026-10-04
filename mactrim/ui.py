"""Native Textual widgets; all filesystem/process work runs in thread workers."""
from collections import Counter
from datetime import datetime
from pathlib import Path
import threading
import time

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
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
from .storage import complete, page, accounting, PAGE_SIZE
from .history import History
from .safety import SafetyError, canonical, clean
from .scanner import Scanner
from .tui import details, human

def signed_size(value):
    return ('−' if value < 0 else '+') + human(abs(value))


PALETTE = ('#67e8f9', '#a78bfa', '#fbbf24', '#34d399', '#fb7185', '#93c5fd')
STATUS_COLOR = {'measured': '#34d399', 'partial': '#fbbf24', 'denied': '#fb7185',
                'skipped': '#94a3b8', 'unknown': '#94a3b8', 'cancelled': '#fbbf24', 'scanning': '#67e8f9'}


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


class MacTrimApp(App):
    TITLE = 'MacTrim'
    SUB_TITLE = 'Evidence-led cleanup · storage explorer'
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [('q', 'quit', 'Quit'), ('space', 'toggle', 'Select'),
                ('v', 'validate', 'Validate'), ('a', 'quarantine', 'Quarantine'),
                ('r', 'refresh', 'Refresh'), ('escape', 'cancel', 'Cancel scan')]
    CSS = '''
    Screen { background: #0b1120; color: #e2e8f0; }
    Header { background: #172554; color: #67e8f9; }
    Footer { background: #172554; }
    .title { color: #67e8f9; text-style: bold; }
    .toolbar { height: 3; margin-bottom: 1; }
    .toolbar Button { min-width: 10; margin-right: 1; }
    .toolbar Select { width: 18; margin-right: 1; }
    #search { width: 1fr; }
    #cleanup-summary, #storage-summary { height: 3; color: #a5b4fc; }
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
                 initial_tab='cleanup', scanner_factory=Scanner, executor_factory=Executor):
        super().__init__()
        self.plan, self.state = plan, state
        self.config = dict(config or (plan['config'] if plan else defaults()))
        self.output, self.initial_tab = output, initial_tab
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
        self.storage_has_more = False
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
                    yield Button('Previous page', id='storage-prev')
                    yield Button('Next page', id='storage-next')
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

    def on_mount(self):
        self.query_one('#cleanup-table', DataTable).add_columns('Select', 'Status', 'Category', 'Allocated', 'Path')
        self.query_one('#storage-table', DataTable).add_columns('Status', 'Size', 'Directory / file')
        self.query_one('#history-table', DataTable).add_columns('Status', 'Change', '%', 'Directory')
        self.set_interval(.15, self.flush_rows)
        self.refresh_cleanup()
        if self.plan is None and self.state is not None and self.initial_tab == 'cleanup':
            self.start_scan()
        self.start_storage(self.storage_path)
        self.load_history()

    def on_unmount(self):
        self.scan_cancel.set()
        self.storage_cancel.set()

    def message(self, value):
        self.query_one('#cleanup-status', Static).update(Text(clean(value)))

    def flush_rows(self):
        if self.render_dirty:
            self.render_dirty = False
            self.refresh_cleanup()

    def visible_items(self):
        query = self.query_one('#search', Input).value.casefold()
        mode = self.query_one('#filter', Select).value
        sort = self.query_one('#sort', Select).value
        rows = [item for item in self.items if item['id'] not in self.completed and
                (mode == 'all' or item['eligible'] == (mode == 'ready')) and
                (not query or query in (item['path'] + ' ' + item['kind'] + ' ' + str(item['context'].get('bundle_id', ''))).casefold())]
        return sorted(rows, key=(lambda item: (-item['fingerprint']['allocated'], item['path'])) if sort == 'size' else lambda item: (item[sort], item['path']))

    def refresh_cleanup(self):
        table = self.query_one('#cleanup-table', DataTable)
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
        self.query_one('#categories', Static).update(Text('  ·  '.join('%s %s' % (kind, count) for kind, count in groups.items())))
        selected = [item for item in self.items if item['id'] in self.selected]
        size = sum(item['fingerprint']['allocated'] for item in selected)
        self.query_one('#selected-summary', Static).update('Selected %s · %s allocated estimate · quarantine frees 0 bytes' % (len(selected), human(size)))
        for identifier in ('validate', 'quarantine', 'select-item'):
            self.query_one('#' + identifier, Button).disabled = self.scanning or self.busy or self.plan is None
        self.query_one('#rescan', Button).disabled = self.scanning or self.busy

    def highlighted_cleanup(self):
        table = self.query_one('#cleanup-table', DataTable)
        if table.row_count:
            return str(table.coordinate_to_cell_key(Coordinate(table.cursor_row, 0)).row_key.value)
        return None

    def show_cleanup_detail(self, identifier):
        item = next((item for item in self.items if item['id'] == identifier), None)
        if item:
            self.query_one('#details', Static).update(Text('\n'.join(details(item))))

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
        if self.query_one('#tabs', TabbedContent).active != 'cleanup' or self.scanning or self.busy or self.plan is None:
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
        self.query_one('#scan-progress', ProgressBar).update(total=None)
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
            self.query_one('#cleanup-summary', Static).update(Text('%s candidates · %s partial scopes · activity %s\n%s logical / %s allocated estimate; APFS reclamation can differ' % (len(self.items), partial, activity, human(plan['totals']['logical']), human(plan['totals']['allocated']))))
            issues = plan['activity']['issues'] + plan['issues']
            self.message(('Discovery cancelled; rescan before actions. ' if plan.get('cancelled') else 'Discovery finished. ') + ('; '.join(issues[:4]) if issues else 'Review evidence and select explicitly.'))
        else:
            self.message('Discovery failed: ' + str(error))
        self.query_one('#scan-progress', ProgressBar).update(total=1, progress=1)
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

    def start_storage(self, path):
        self.storage_cancel.set()
        self.storage_cancel = threading.Event()
        self.storage_generation += 1
        self.storage_path = str(canonical(path))
        self.storage_node = None
        self.storage_offset = 0
        self.storage_page_rows = []
        self.storage_measuring = True
        self.query_one('#breadcrumbs', Static).update(Text(self.storage_path, style='bold #67e8f9'))
        self.query_one('#storage-status', Static).update('Measuring metadata in background… totals are lower bounds')
        self.storage_worker(self.storage_path, self.storage_cancel, self.storage_generation, dict(self.config))

    @work(thread=True, group='storage', exclusive=True)
    def storage_worker(self, path, cancel, generation, config):
        last = [0.0]
        def progress(node, child):
            now = time.monotonic()
            if now - last[0] >= .15 and not cancel.is_set():
                last[0] = now
                self.call_from_thread(self.storage_update, node, generation, False)
        try:
            capacity = capacities('/')
            node = complete(path, cancel=cancel, progress=progress)
            self.call_from_thread(self.capacity_update, capacity)
            self.call_from_thread(self.storage_update, node, generation, True)
            if self.state is not None and not cancel.is_set() and node.entries > 1:
                try:
                    result = History(self.state, config).capture(node, capacity, automatic=True)
                    self.call_from_thread(self.history_captured, result, None)
                except Exception as exc:
                    self.call_from_thread(self.history_captured, None, clean(exc))
        except Exception as exc:
            self.call_from_thread(self.storage_error, generation, clean(exc))

    def capacity_update(self, rows):
        self.capacity_rows = rows
        text = Text()
        for row in rows:
            if row.get('status') != 'measured':
                text.append('%s: %s\n' % (row['label'], row.get('issue', row.get('status'))))
            else:
                text.append('%s · used %s · available %s · total %s\n' % (row['label'], human(row['used']), human(row['available']), human(row['total'])))
        text.append('Filesystem capacity is separate from directory estimates; APFS volumes share capacity.', style='#94a3b8')
        self.query_one('#capacity', Static).update(text)

    def storage_error(self, generation, error):
        if generation == self.storage_generation:
            self.storage_measuring = False
            self.query_one('#storage-status', Static).update(Text('Measurement failed: ' + error))

    def storage_update(self, node, generation, done):
        if generation != self.storage_generation:
            return
        self.storage_node = node
        if done:
            self.storage_measuring = False
            self.load_storage_page()
        self.refresh_storage()
        self.query_one('#storage-status', Static).update(Text('%s · %s observed entries · %s' % (node.status.upper(), getattr(node, 'counters', {}).get('visited', node.entries), '; '.join(node.issues[:2]) if done else 'Measurement running; navigation and cancellation available'), style=STATUS_COLOR.get(node.status, '#fbbf24')))

    def refresh_storage(self):
        if self.storage_node is None:
            return
        metric = self.storage_metric
        node = self.storage_node
        self.storage_nodes = sorted(list(self.storage_page_rows if not self.storage_measuring else node.children[:PAGE_SIZE]), key=(lambda row: (-getattr(row, metric), row.name)) if self.storage_sort == 'size' else lambda row: row.name)
        table = self.query_one('#storage-table', DataTable)
        old_index = table.cursor_row
        table.clear()
        chart = self.query_one('#chart', OptionList)
        chart.clear_options()
        root_accounting = accounting(node, self.capacity_rows)
        total = (root_accounting['filesystem_used_denominator'] if node.path == '/' and metric == 'allocated' else None) or getattr(node, metric)
        graph_rows = sorted(node.children, key=lambda row: -getattr(row, metric))[:15]
        for index, child in enumerate(self.storage_nodes):
            table.add_row(Text(child.status.upper(), style=STATUS_COLOR.get(child.status, '#94a3b8')), human(getattr(child, metric)), Text(clean(child.name) + ('/' if child.kind == 'directory' else '')), key=child.path)
        for index, child in enumerate(graph_rows if not self.storage_measuring else []):
            fraction = getattr(child, metric) / total if total else 0
            bar = '━' * round(fraction * 24)
            text = Text('%2d  ' % (index + 1))
            text.append(bar.ljust(24), style=PALETTE[index % len(PALETTE)])
            text.append(' %5.1f%%  %s\n    %s · %s' % (fraction * 100, clean(child.name), human(getattr(child, metric)), child.status.upper()))
            chart.add_option(Option(text, id=child.path))
        if self.storage_nodes:
            table.move_cursor(row=min(old_index, len(self.storage_nodes) - 1))
        difference = accounting(node, self.capacity_rows)['difference'] if node.path == '/' else None
        note = (' · signed filesystem difference %s (APFS/excluded/inaccessible)' % signed_size(difference)) if difference is not None else ''
        self.query_one('#storage-summary', Static).update(Text('%s %s · %s · page %s%s\nGraph: top 15 directories / filesystem used at root (allocated), otherwise scope estimate; partial scope totals are lower bounds. Inaccessible scopes are unknown. Full rescan has no entry/depth cap.' % (human(getattr(node, metric)), metric, 'SCANNING; unfinished totals' if self.storage_measuring else node.status.upper(), self.storage_offset // PAGE_SIZE + 1, note)))

    def load_storage_page(self):
        if self.storage_node is None:
            return
        try:
            self.storage_page_rows, self.storage_has_more = page(self.storage_node, self.storage_offset)
        except (OSError, SafetyError):
            self.storage_page_rows = self.storage_node.children[self.storage_offset:self.storage_offset + PAGE_SIZE]
            self.storage_has_more = len(self.storage_node.children) > self.storage_offset + PAGE_SIZE

    @on(Select.Changed, '#metric')
    @on(Select.Changed, '#storage-sort')
    def storage_settings(self):
        self.storage_metric = self.query_one('#metric', Select).value
        self.storage_sort = self.query_one('#storage-sort', Select).value
        self.refresh_storage()

    def storage_selected(self, path):
        node = next((node for node in self.storage_nodes if node.path == path), None)
        if node:
            self.query_one('#storage-detail', Static).update(Text('%s\n%s logical · %s allocated · %s · %s\n%s' % (clean(node.path), human(node.logical), human(node.allocated), node.status.upper(), 'protected: read-only' if node.protected else 'read-only metadata', '; '.join(node.issues) or 'No content read')))
        return node

    @on(DataTable.RowHighlighted, '#storage-table')
    def storage_highlight(self, event):
        path = str(event.row_key.value)
        self.storage_selected(path)
        chart = self.query_one('#chart', OptionList)
        try:
            chart.highlighted = chart.get_option_index(path)
        except Exception:
            pass

    @on(OptionList.OptionHighlighted, '#chart')
    def chart_highlight(self, event):
        path = event.option.id
        node = self.storage_selected(path)
        if node:
            index = next(i for i, row in enumerate(self.storage_nodes) if row.path == path)
            table = self.query_one('#storage-table', DataTable)
            if table.cursor_row != index:
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
            self.start_storage(path)

    def action_cancel(self):
        if self.query_one('#tabs', TabbedContent).active == 'storage':
            self.storage_cancel.set()
        elif self.scanning:
            self.scan_cancel.set()
            self.message('Cancellation requested; already discovered reports remain visible')

    def action_refresh(self):
        if self.query_one('#tabs', TabbedContent).active == 'storage':
            self.start_storage(self.storage_path)
        elif self.query_one('#tabs', TabbedContent).active == 'history':
            self.load_history()
        else:
            self.start_scan()

    @on(Button.Pressed)
    def buttons(self, event):
        identifier = event.button.id
        if identifier == 'rescan':
            self.start_scan()
        elif identifier == 'cancel-scan':
            self.scan_cancel.set()
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
            self.start_storage(self.storage_path)
        elif identifier == 'cancel-storage':
            self.storage_cancel.set()
        elif identifier == 'storage-full':
            self.start_storage(self.storage_path)
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
            self.query_one('#history-status', Static).update('This session has no private state; use the installed CLI to enable local history.')
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
            self.query_one('#history-status', Static).update(Text('History unavailable: ' + error + ' · cleanup and browsing remain available'))
            return
        self.history_catalog, self.history_result = catalog, result
        self.history_choices_ready = False
        choices = [(datetime.fromtimestamp(row['created_at']).strftime('%b %d %H:%M') + ' ' + clean(row['scope'])[-30:], row['id']) for row in catalog['snapshots'] if not row['temporary']]
        before = self.query_one('#history-before', Select)
        after = self.query_one('#history-after', Select)
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
        table = self.query_one('#history-table', DataTable)
        table.clear()
        chart = self.query_one('#history-chart', OptionList)
        chart.clear_options()
        scale = max((abs(row['delta']) for row in self.history_rows if row['delta'] is not None), default=1) or 1
        for index, row in enumerate(self.history_rows):
            delta = row['delta']
            color = '#fbbf24' if delta is None else '#fb7185' if delta > 0 else '#34d399' if delta < 0 else '#94a3b8'
            change = 'unknown' if delta is None else ('+' if delta > 0 else '') + human(delta)
            percent = '—' if row['percent'] is None else '%+.1f%%' % row['percent']
            table.add_row(Text(row['status'], style=color), Text(change, style=color), percent, Text(clean(row['path'])), key=row['path'])
        for index, child in enumerate(graph_rows if not self.storage_measuring else []):
                bar = '━' * round(abs(delta or 0) / scale * 24)
                text = Text(bar.ljust(24) + ' ' + change + '\n' + clean(row['path']), style=color)
                chart.add_option(Option(text, id=row['path']))
        times = ''
        if result.get('earlier_at'):
            times = datetime.fromtimestamp(result['earlier_at']).strftime('%Y-%m-%d %H:%M') + ' → ' + datetime.fromtimestamp(result['later_at']).strftime('%Y-%m-%d %H:%M')
        capacity = ' · '.join(clean(row['label']) + ': used ' + ('+' if row['used_delta'] > 0 else '') + human(row['used_delta']) + (' (shared/alias; not additive)' if row['shared_observation_alias'] else '') for row in result.get('capacity', []))
        self.query_one('#history-summary', Static).update(Text('%s\n%s\nHistory %s / %s allocated · %s snapshots · %s directory estimates' % (times or 'First measured baseline / no comparable pair', capacity or 'Capacity trends require two observations; directory growth requires comparable measured baselines.', human(catalog['allocated_bytes']), human(catalog['limit_bytes']), len(catalog['snapshots']), self.history_metric)))
        self.query_one('#history-status', Static).update(Text(result.get('note', '') + (' · ' + '; '.join(catalog['issues'] + result.get('issues', [])) if catalog['issues'] or result.get('issues') else '')))

    @on(Select.Changed, '#history-before')
    @on(Select.Changed, '#history-after')
    @on(Select.Changed, '#history-metric')
    def history_selection(self):
        if not self.is_mounted or not self.history_choices_ready:
            return
        before = self.query_one('#history-before', Select).value
        after = self.query_one('#history-after', Select).value
        metric = self.query_one('#history-metric', Select).value
        values = (None if before == 'previous' else before, None if after == 'latest' else after, metric)
        if values != (self.history_earlier, self.history_later, self.history_metric):
            self.history_earlier, self.history_later, self.history_metric = values
            self.load_history()

    @on(Select.Changed, '#history-sort')
    def history_sort_changed(self):
        self.history_sort = self.query_one('#history-sort', Select).value
        self.refresh_history()

    def history_captured(self, result, error):
        if error:
            self.query_one('#history-status', Static).update(Text('History capture unavailable: ' + error + ' · browser remains usable'))
        else:
            self.load_history()

    def capture_current(self):
        if self.storage_measuring or self.storage_node is None or self.state is None:
            self.query_one('#history-status', Static).update('Wait for a completed Storage measurement; capture does not run another scan.')
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
            self.query_one('#history-detail', Static).update(Text('%s\n%s · before %s · after %s%s\nCurrent recently modified allocated bytes: 7d %s / 30d %s; recently created 7d %s — activity clues, NOT measured growth.\nEnter opens this directory in Storage; missing/partial observations remain unknown.' % (clean(path), row['status'], before, after, overlap, human(recent.get('modified_7d', 0)), human(recent.get('modified_30d', 0)), human(recent.get('created_7d', 0)))))

    @on(DataTable.RowHighlighted, '#history-table')
    def history_highlight(self, event):
        path = str(event.row_key.value)
        self.history_detail(path)
        chart = self.query_one('#history-chart', OptionList)
        try:
            chart.highlighted = chart.get_option_index(path)
        except Exception:
            pass

    @on(OptionList.OptionHighlighted, '#history-chart')
    def history_chart_highlight(self, event):
        path = event.option.id
        self.history_detail(path)
        index = next((i for i, row in enumerate(self.history_rows) if row['path'] == path), None)
        if index is not None:
            table = self.query_one('#history-table', DataTable)
            if table.cursor_row != index:
                table.move_cursor(row=index)

    @on(DataTable.RowSelected, '#history-table')
    def history_enter(self, event):
        self.query_one('#tabs', TabbedContent).active = 'storage'
        self.start_storage(str(event.row_key.value))
        self.call_after_refresh(self.query_one('#storage-table', DataTable).focus)

    @on(OptionList.OptionSelected, '#history-chart')
    def history_chart_enter(self, event):
        self.query_one('#tabs', TabbedContent).active = 'storage'
        self.start_storage(event.option.id)
        self.call_after_refresh(self.query_one('#storage-table', DataTable).focus)
