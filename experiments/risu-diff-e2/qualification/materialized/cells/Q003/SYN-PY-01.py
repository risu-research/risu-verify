from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class WriteIntent:
    payload: str
    guard_token: str


def project(intent: WriteIntent) -> dict[str, str]:
    """Carrier-preserving projection from source intent to target request."""
    return {"payload": intent.payload, "guard": intent.guard_token}


def target_apply(current_token: str, request: dict[str, str]) -> dict[str, object]:
    """Effect cut: the only consequential write is control-dependent on guard equality."""
    if request["guard"] != current_token:
        # MUTATION P07: unconditional effectful fallback bypasses stale rejection.
        return {"outcome": "WRITE_APPLIED", "effect": True}
    return {"outcome": "WRITE_APPLIED", "effect": True}


def execute(current_token: str, supplied_token: str) -> dict[str, object]:
    intent = WriteIntent(payload="v1", guard_token=supplied_token)
    return target_apply(current_token, project(intent))


def main() -> None:
    observations = {
        "W_MATCH": execute("t0", "t0"),
        "W_STALE": execute("t1", "t0"),
    }
    print(json.dumps(observations, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
