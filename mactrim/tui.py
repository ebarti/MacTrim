"""Keyboard-first review. No default selection; exact approval before moving."""
import curses
import sys
import textwrap

from .executor import Executor, selection
from .safety import SafetyError, clean


def human(number):
    value = float(number)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            return "%0.1f %s" % (value, unit)
        value /= 1024


def details(item):
    lines = ["FULL PATH", clean(item["path"]), "", "CLASSIFICATION", clean(item["kind"]),
             "Actionable" if item["eligible"] else "Report only / blocked", "",
             "ESTIMATED SIZE", "Logical %s  /  Allocated %s" % (human(item["fingerprint"]["logical"]), human(item["fingerprint"]["allocated"])),
             "Quarantine frees 0 bytes", "", "EVIDENCE"]
    lines += ["- " + clean(value) for value in item["evidence"]] or ["No provenance established"]
    if item["context"].get("keeper"):
        lines += ["", "PROTECTED KEEPER", clean(item["context"]["keeper"]), "SHA-256 " + item["context"]["sha256"]]
    if item["blockers"]:
        lines += ["", "BLOCKERS"] + ["- " + clean(value) for value in item["blockers"]]
    lines += ["", "REGENERATION / REVIEW", clean(item["hint"]), "", "FINGERPRINT", str(item["fingerprint"]["digest"])]
    return lines


class Review:
    def __init__(self, screen, plan, state):
        self.screen = screen
        self.plan = plan
        self.executor = Executor(state)
        self.selected = set()
        self.completed = set()
        self.cursor = 0
        self.detail_scroll = 0
        self.sort_size = True
        self.mode = 0
        self.search = ""
        self.message = "Nothing selected. Space selects actionable items; review-only items are protected."
        self.color = False

    def rows(self):
        items = [item for item in self.plan["candidates"] if item["id"] not in self.completed]
        if self.mode == 1:
            items = [item for item in items if item["eligible"]]
        elif self.mode == 2:
            items = [item for item in items if not item["eligible"]]
        if self.search:
            items = [item for item in items if self.search.casefold() in clean(item["path"]).casefold() or self.search.casefold() in item["kind"].casefold()]
        return sorted(items, key=(lambda item: (-item["fingerprint"]["allocated"], item["path"])) if self.sort_size else lambda item: item["path"])

    def draw(self, y, x, value, width=None, style=0):
        height, columns = self.screen.getmaxyx()
        if y < 0 or y >= height or x < 0 or x >= columns:
            return
        width = min(columns - x - 1, width if width is not None else columns - x - 1)
        if width <= 0:
            return
        try:
            self.screen.addnstr(y, x, clean(value), width, style)
        except curses.error:
            pass

    def prompt(self, title):
        value = ""
        while True:
            height, width = self.screen.getmaxyx()
            for y in (height - 3, height - 2):
                self.screen.move(max(0, y), 0)
                self.screen.clrtoeol()
            self.draw(height - 3, 1, title, style=curses.A_BOLD)
            self.draw(height - 2, 1, "> " + value)
            self.screen.refresh()
            key = self.screen.get_wch()
            if key in ("\n", "\r"):
                return value
            if key == "\x1b":
                return None
            if key in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                value = value[:-1]
            elif isinstance(key, str) and key.isprintable() and len(value) < 200:
                value += key

    def paint(self):
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        accent = curses.color_pair(1) if self.color else curses.A_BOLD
        muted = curses.color_pair(2) if self.color else curses.A_DIM
        good = curses.color_pair(3) if self.color else curses.A_BOLD
        self.draw(0, 1, "MACTRIM  /  evidence-led cleanup", style=accent | curses.A_BOLD)
        totals = self.plan["totals"]
        self.draw(1, 1, "%s logical  |  %s allocated estimate  |  Quarantine frees 0 bytes" % (human(totals["logical"]), human(totals["allocated"])), style=muted)
        if height < 12 or width < 60:
            self.draw(3, 1, "Resize terminal to at least 60 columns x 12 rows. q exits.")
            self.screen.refresh()
            return
        items = self.rows()
        self.cursor = min(self.cursor, max(0, len(items) - 1))
        mode = ("All", "Actionable", "Reports")[self.mode]
        self.draw(3, 1, "%s  |  Sort: %s  |  %s items  |  Filter: %s" % (mode, "size" if self.sort_size else "path", len(items), self.search or "none"), style=accent)
        split = max(31, int(width * .47)) if width >= 95 else width
        list_width = split - 2
        visible = height - 9
        first = max(0, self.cursor - visible + 1)
        for position, item in enumerate(items[first:first + visible], first):
            y = 5 + position - first
            marker = "[x]" if item["id"] in self.selected else "[ ]" if item["eligible"] else " - "
            state = "ready" if item["eligible"] else "review"
            display = "%s %7s %6s %s" % (marker, human(item["fingerprint"]["allocated"]), state, item["path"])
            style = curses.A_REVERSE if position == self.cursor else good if item["eligible"] else muted
            self.draw(y, 1, display, list_width, style)
        if not items:
            self.draw(5, 1, "No candidates match. f cycles filters; / searches.", list_width, muted)
        if width >= 95:
            for y in range(4, height - 4):
                self.draw(y, split, "|", 1, muted)
            if items:
                lines = []
                for line in details(items[self.cursor]):
                    lines.extend(textwrap.wrap(line, max(10, width - split - 4), replace_whitespace=False) or [""])
                for index, line in enumerate(lines[self.detail_scroll:self.detail_scroll + visible + 1]):
                    self.draw(4 + index, split + 2, line)
                self.draw(height - 5, split + 2, "[ / ] scroll detail", style=muted)
        selected_items = [item for item in self.plan["candidates"] if item["id"] in self.selected]
        size = sum(item["fingerprint"]["allocated"] for item in selected_items)
        self.draw(height - 4, 1, "Selected %s  |  %s allocated estimate  |  %s" % (len(self.selected), human(size), "Activity complete for current UID" if self.plan["activity"]["complete"] else "Activity incomplete: actions blocked"), style=accent)
        self.draw(height - 3, 1, self.message)
        self.draw(height - 2, 1, "j/k move  SPACE select  s sort  f filter  / search  d detail  v validate  a move  q quit", style=muted)
        self.screen.refresh()

    def run(self):
        curses.curs_set(0)
        self.screen.keypad(True)
        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
                curses.init_pair(1, curses.COLOR_CYAN, -1)
                curses.init_pair(2, curses.COLOR_WHITE, -1)
                curses.init_pair(3, curses.COLOR_GREEN, -1)
                self.color = True
            except curses.error:
                pass
        while True:
            self.paint()
            key = self.screen.get_wch()
            items = self.rows()
            if key in ("q", "Q", "\x1b"):
                return 0
            if key in ("j", curses.KEY_DOWN):
                self.cursor = min(self.cursor + 1, max(0, len(items) - 1))
                self.detail_scroll = 0
            elif key in ("k", curses.KEY_UP):
                self.cursor = max(0, self.cursor - 1)
                self.detail_scroll = 0
            elif key == " ":
                if items:
                    item = items[self.cursor]
                    if not item["eligible"]:
                        self.message = "Report-only item cannot be selected: " + "; ".join(item["blockers"])
                    elif item["id"] in self.selected:
                        self.selected.remove(item["id"])
                        self.message = "Deselected " + item["path"]
                    else:
                        proposed = list(self.selected | {item["id"]})
                        try:
                            selection(self.plan, proposed)
                            self.selected.add(item["id"])
                            self.message = "Selected " + item["path"]
                        except SafetyError as exc:
                            self.message = str(exc)
            elif key == "s":
                self.sort_size = not self.sort_size
                self.cursor = 0
            elif key == "f":
                self.mode = (self.mode + 1) % 3
                self.cursor = 0
            elif key == "/":
                value = self.prompt("Search path or detector (empty clears; Esc cancels)")
                if value is not None:
                    self.search = value
                    self.cursor = 0
            elif key in ("[", "]"):
                self.detail_scroll = max(0, self.detail_scroll + (-5 if key == "[" else 5))
            elif key == "d" and items:
                # Full-screen detail makes every field available on narrow terminals.
                lines = details(items[self.cursor])
                page = 0
                while True:
                    self.screen.erase()
                    height, width = self.screen.getmaxyx()
                    wrapped = []
                    for line in lines:
                        wrapped.extend(textwrap.wrap(line, max(10, width - 4), replace_whitespace=False) or [""])
                    for index, line in enumerate(wrapped[page:page + height - 3]):
                        self.draw(index, 1, line)
                    self.draw(height - 2, 1, "j/k scroll   q/Esc return")
                    self.screen.refresh()
                    detail_key = self.screen.get_wch()
                    if detail_key in ("q", "\x1b"):
                        break
                    if detail_key in ("j", curses.KEY_DOWN):
                        page = min(page + 1, max(0, len(wrapped) - height + 3))
                    elif detail_key in ("k", curses.KEY_UP):
                        page = max(0, page - 1)
            elif key in ("v", "a"):
                try:
                    result = self.executor.dry_run(self.plan, sorted(self.selected))
                    self.message = "Validated. Quarantine frees 0 bytes. Approval: " + result["approval"]
                    if key == "a":
                        value = self.prompt("Type exactly: " + result["approval"] + " (Esc cancels)")
                        if value is None:
                            self.message = "Cancelled; no items moved"
                        else:
                            applied = self.executor.apply(self.plan, sorted(self.selected), value)
                            moved_paths = {row["path"] for row in applied["outcomes"] if row["status"] == "quarantined"}
                            self.completed |= {item["id"] for item in self.plan["candidates"] if item["path"] in moved_paths}
                            self.selected -= self.completed
                            self.message = "; ".join(row["status"] + ": " + row.get("reason", row["path"]) for row in applied["outcomes"])
                except (OSError, SafetyError) as exc:
                    self.message = "Blocked: " + clean(exc)


def review(plan, state):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SafetyError("TUI requires an interactive terminal. Use review PLAN --details or scan --output PLAN.")
    try:
        return curses.wrapper(lambda screen: Review(screen, plan, state).run())
    except curses.error as exc:
        raise SafetyError("Terminal cannot start curses; use textual review --details (%s)" % clean(exc)) from exc
