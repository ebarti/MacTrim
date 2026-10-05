"""Standalone entry, including its private native event receiver."""
import sys

if __name__ == '__main__':
    if sys.argv[1:] == ['--mactrim-event-receiver']:
        from mactrim.event_receiver import main
    else:
        from mactrim.cli import main
    raise SystemExit(main())
