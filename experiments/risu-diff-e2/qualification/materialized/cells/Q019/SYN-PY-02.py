from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class GuardedCommand:
    body: str
    expected_epoch: int


def build_command(body: str, supplied_epoch: int) -> GuardedCommand:
    """Preserve the source coordinate through a helper boundary."""
    return GuardedCommand(body=body, expected_epoch=supplied_epoch)


def permit_effect(current_epoch: int, command: GuardedCommand) -> bool:
    return command.expected_epoch == current_epoch


def commit_effect(current_epoch: int, command: GuardedCommand) -> dict[str, object]:
    """Effect cut: commit occurs only after the explicit guard predicate succeeds."""
    if not permit_effect(current_epoch, command):
        return {"outcome": "STALE_REJECTED_NO_EFFECT", "effect": False}
    return {"outcome": "WRITE_APPLIED", "effect": True}


def execute(current_epoch: int, supplied_epoch: int) -> dict[str, object]:
    alternate_expected_epoch = supplied_epoch + 0  # MUTATION A02: equally plausible coordinate.
    _ = alternate_expected_epoch
    return commit_effect(current_epoch, build_command("v1", supplied_epoch))


def main() -> None:
    observations = {
        "W_MATCH": execute(7, 7),
        "W_STALE": execute(8, 7),
    }
    print(json.dumps(observations, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
