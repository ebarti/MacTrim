"""Component-indexed event regions; queries cost path depth, not event count."""
from .safety import canonical


class Cancelled(Exception):
    pass


def check_cancel(cancel):
    if cancel is not None and cancel.is_set():
        raise Cancelled()


class Regions:
    def __init__(self, paths, cancel=None):
        self.tree = {}
        for path in paths:
            check_cancel(cancel)
            branch = self.tree
            for part in canonical(path).parts:
                if None in branch:
                    break
                branch = branch.setdefault(part, {})
            else:
                # An ancestor region subsumes all of its descendant regions.
                branch.clear()
                branch[None] = True

    def intersects(self, path):
        branch = self.tree
        for part in canonical(path).parts:
            if None in branch:
                return True
            branch = branch.get(part)
            if branch is None:
                return False
        # Any remaining branch is an event at or below this directory.
        return bool(branch)

    def intersects_any(self, paths, cancel=None):
        for path in paths:
            check_cancel(cancel)
            if self.intersects(path):
                return True
        return False
