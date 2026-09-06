"use strict";

function request(payload, expectedGeneration) {
  return { payload, expectedGeneration };
}

function clientGuardedWrite(currentGeneration, req) {
  const guardOk = req.expectedGeneration === currentGeneration; // MUTATION P09
  void guardOk;
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
