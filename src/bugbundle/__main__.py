"""Allow ``python -m bugbundle``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
