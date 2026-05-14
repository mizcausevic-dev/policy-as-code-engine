"""
Entry point. Either run the HTTP API or evaluate a bundle from the CLI.

    # API
    python -m policy_as_code_engine                          # binds 0.0.0.0:8089

    # CLI eval
    python -m policy_as_code_engine eval bundle.yaml ctx.json
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .evaluator import PolicyEvaluator
from .loader import load_bundle_from_file
from .models import EvaluationContext


def _serve() -> None:
    import uvicorn

    port = int(os.environ.get("PORT", "8089"))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run("policy_as_code_engine.app:app", host=host, port=port, log_level="info")


def _eval(bundle_path: str, context_path: str) -> int:
    bundle = load_bundle_from_file(bundle_path)
    raw_ctx = Path(context_path).read_text(encoding="utf-8")
    context = EvaluationContext.model_validate_json(raw_ctx)
    result = PolicyEvaluator().evaluate(bundle, context)
    print(json.dumps(result.model_dump(mode="json"), indent=2))
    return 0 if result.decision.kind != "deny" else 1


def main() -> None:
    args = sys.argv[1:]
    if not args:
        _serve()
        return
    if args[0] == "eval" and len(args) == 3:
        sys.exit(_eval(args[1], args[2]))
    print("usage: python -m policy_as_code_engine                # run HTTP API")
    print("       python -m policy_as_code_engine eval BUNDLE CTX  # CLI eval")
    sys.exit(2)


if __name__ == "__main__":
    main()
