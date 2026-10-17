"""Private pipe protocol. No filesystem event log, scanner, TUI or disk writes."""
import json
import sys
from .events import EventCollector
from .safety import clean


def main():
    collector = None
    def reply(value):
        if collector is not None:
            value['diagnostics'] = dict(collector.diagnostics, receiver_pid=__import__('os').getpid())
        sys.stdout.write(json.dumps(value) + '\n')
        sys.stdout.flush()
    try:
        setup = json.loads(sys.stdin.buffer.readline())
        collector = EventCollector(setup['root'], setup['since'], setup['exclusions'])
        with collector:
            reply({'ready': True})
            for line in sys.stdin.buffer:
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


if __name__ == '__main__':
    raise SystemExit(main())
