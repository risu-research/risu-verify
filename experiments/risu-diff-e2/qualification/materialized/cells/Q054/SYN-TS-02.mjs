"use strict";

function request(payload, expected_generation_wire) {
  return { payload, expected_generation_wire };
}

function clientGuardedWrite(currentGeneration, req) {
  // Effect cut: stale and success are distinct target outcomes.
  if (req.expected_generation_wire !== currentGeneration) {
    return { ok: false, kind: "STALE", effect: false };
  }
  return { ok: true, kind: "APPLIED", effect: true };
}

function service(currentGeneration, suppliedGeneration) {
  const result = clientGuardedWrite(
    currentGeneration,
    request("v1", suppliedGeneration)
  );

  // Interpretation boundary preserves the stale-versus-applied distinction.
  if (!result.ok && result.kind === "STALE") {
    return { outcome: "STALE_REJECTED_NO_EFFECT", effect: false };
  }
  if (result.ok && result.kind === "APPLIED") {
    return { outcome: "WRITE_APPLIED", effect: true };
  }
  return { outcome: "UNEXPECTED", effect: result.effect };
}

const observations = {
  W_MATCH: service(3, 3),
  W_STALE: service(4, 3),
};

process.stdout.write(JSON.stringify(observations) + "\n");
