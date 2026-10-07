"""Top-level redirect package shim to allow execution via `python -m src.portscope`."""

from portscope.cli import main

if __name__ == "__main__":
    import sys
    sys.exit(main())
