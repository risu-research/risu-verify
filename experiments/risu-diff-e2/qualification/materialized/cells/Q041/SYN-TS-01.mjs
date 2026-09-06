"use strict";

function makeIntent(payload, guardStamp) {
  return Object.freeze({ payload, guardStamp });
}

function serialize(intent) {
  // Explicit representation mapping preserves the consequential carrier.
  return { body: intent.payload, wire_guard: intent.guardStamp };
}

function targetApply(currentStamp, wireRequest) {
  const applied = { outcome: "WRITE_APPLIED", effect: true }; // MUTATION P06
  if (wireRequest.wire_guard !== currentStamp) return applied;
  return applied;
}

function execute(currentStamp, suppliedStamp) {
  return targetApply(currentStamp, serialize(makeIntent("v1", suppliedStamp)));
}

const observations = {
  W_MATCH: execute("s0", "s0"),
  W_STALE: execute("s1", "s0"),
};

process.stdout.write(JSON.stringify(observations) + "\n");
