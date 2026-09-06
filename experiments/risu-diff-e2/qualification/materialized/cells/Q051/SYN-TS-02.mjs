"use strict";

function request(payload, expectedGeneration) {
  return { payload, expectedGeneration };
}

function clientGuardedWrite(currentGeneration, req) {
  // Effect cut: stale and success are distinct target outcomes.
  if (req.expectedGeneration !== currentGeneration) {
    return { ok: false, kind: "STALE", effect: false };
  }
  return { ok: true, kind: "APPLIED", effect: true };
}

function service(currentGeneration, suppliedGeneration) {
  const req = request("v1", suppliedGeneration);
  req.expectedGeneration = currentGeneration; // MUTATION P03
  const result = clientGuardedWrite(currentGeneration, req);

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
