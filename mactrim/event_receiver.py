"""Private pipe protocol. No filesystem event log, scanner, TUI or disk writes."""
import json
import os
import queue
import sys
import threading
from .events import EventCollector
from .safety import clean


def main():
    collector = None
    finished = threading.Event()
    requests = queue.Queue(maxsize=1)  # Client permits one outstanding request.
    def reply(value):
        if collector is not None:
            value['diagnostics'] = dict(collector.diagnostics, receiver_pid=os.getpid())
        sys.stdout.write(json.dumps(value) + '\n')
        sys.stdout.flush()
    def read_commands():
        try:
            for line in sys.stdin.buffer:
                requests.put(line)
        finally:
            requests.put(None)
            # EOF must also stop an orphan whose control thread is stuck in a
            # native flush. Normal cleanup gets two seconds; OS exit releases
            # native resources if it cannot complete. No parent PID guessing.
            if not finished.wait(2):
                os._exit(0)
    try:
        setup = json.loads(sys.stdin.buffer.readline())
        collector = EventCollector(setup['root'], setup['since'], setup['exclusions'])
        with collector:
            threading.Thread(target=read_commands, name='mactrim-parent-connection', daemon=True).start()
            reply({'ready': True})
            while True:
                line = requests.get()
                if line is None: break
                request = json.loads(line)
                if request.get('command') != 'drain':
                    raise ValueError('Unknown receiver command')
                paths, issues, latest = collector.drain()
                reply({'paths': sorted(paths), 'issues': issues, 'latest': latest})
        return 0
    except Exception as exc:
        try: reply({'error': clean(exc)})
        except (BrokenPipeError, OSError): pass
        return 2
    finally:
        finished.set()


if __name__ == '__main__':
    raise SystemExit(main())
