"""`python -m firewall.service --host 127.0.0.1 --port 8787 --policy all [--audit PATH]`"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m firewall.service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--policy", default="all")
    parser.add_argument("--audit", type=Path, default=None, help="audit JSONL path (default runs/service/)")
    args = parser.parse_args(argv)
    import uvicorn

    from firewall.service.app import create_app

    # Single worker, asyncio loop (no uvloop on Windows); sessions live in this process.
    uvicorn.run(create_app(policy=args.policy, audit_path=args.audit), host=args.host, port=args.port,
                workers=1, loop="asyncio", log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
