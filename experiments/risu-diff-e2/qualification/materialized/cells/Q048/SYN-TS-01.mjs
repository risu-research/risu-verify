"use strict";

function makeIntent(payload, guardStamp) {
  return Object.freeze({ payload, guardStamp });
}

function serialize(intent) {
  // Explicit representation mapping preserves the consequential carrier.
  return { body: intent.payload, wire_guard: intent.guardStamp };
}

function targetApply(currentStamp, wireRequest) {
  // Effect cut: the only write is guarded by the serialized carrier.
  if (wireRequest.wire_guard !== currentStamp) {
    return { outcome: "STALE_REJECTED_NO_EFFECT", effect: false };
  }
  return { outcome: "WRITE_APPLIED", effect: true };
}

function execute(currentStamp, suppliedStamp) {
  const alternateGuardStamp = suppliedStamp; // MUTATION A02: equally plausible coordinate.
  void alternateGuardStamp;
  return targetApply(currentStamp, serialize(makeIntent("v1", suppliedStamp)));
}

const observations = {
  W_MATCH: execute("s0", "s0"),
  W_STALE: execute("s1", "s0"),
};

process.stdout.write(JSON.stringify(observations) + "\n");
