#!/usr/bin/env node
"use strict";

/*
 * C3 R0 W9 orthogonal exhaustive reference evaluator.
 *
 * This program deliberately knows nothing about W7/W8/W5/W6, MFST JSON,
 * C2 normalization, graph commitments, K1 consequence hashes, or RISU
 * checker code. It enumerates the frozen R0 descriptor algebra and computes
 * exact ordered payload traces by two independent internal formulations:
 *   (A) Boolean transition equations
 *   (B) explicit finite truth tables
 * Any disagreement aborts before a reference digest is emitted.
 */

const fs = require("fs");
const crypto = require("crypto");

const AX = {
  initial_q: ["C0", "C1", "X"],
  update: ["KEEP", "CONST0", "CONST1", "COPY_X", "NOT_Q_TABLE", "ID_Q_TABLE", "XOR_QX_TABLE", "AND_QX_TABLE"],
  predicate: ["X_EQ0", "X_EQ1", "Q_EQ0", "Q_EQ1", "WORLD_EQ0", "WORLD_EQ1"],
  prefix: ["NONE", "E3"],
  trace: ["A", "B", "AB", "BA", "AA", "BB", "ABA", "BAB"],
};
const EFFECTS = {
  A: ["01"],
  B: ["02"],
  AB: ["01", "02"],
  BA: ["02", "01"],
  AA: ["01", "01"],
  BB: ["02", "02"],
  ABA: ["01", "02", "01"],
  BAB: ["02", "01", "02"],
};
const POINTS = [
  {point_symbol:"W0/X0", world_symbol:"W0", x_symbol:"X0", w:0, x:0},
  {point_symbol:"W0/X1", world_symbol:"W0", x_symbol:"X1", w:0, x:1},
  {point_symbol:"W1/X0", world_symbol:"W1", x_symbol:"X0", w:1, x:0},
  {point_symbol:"W1/X1", world_symbol:"W1", x_symbol:"X1", w:1, x:1},
];

function die(msg) { throw new Error(msg); }

function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    const ks = Object.keys(value).sort();
    return "{" + ks.map(k => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  return JSON.stringify(value);
}

function initFormula(init, x) {
  switch (init) {
    case "C0": return 0;
    case "C1": return 1;
    case "X": return x;
    default: die("bad initial " + init);
  }
}
function updateFormula(op, q, x) {
  switch (op) {
    case "KEEP": return q;
    case "CONST0": return 0;
    case "CONST1": return 1;
    case "COPY_X": return x;
    case "NOT_Q_TABLE": return 1 - q;
    case "ID_Q_TABLE": return q;
    case "XOR_QX_TABLE": return q ^ x;
    case "AND_QX_TABLE": return q & x;
    default: die("bad update " + op);
  }
}
function predFormula(p, w, x, q) {
  switch (p) {
    case "X_EQ0": return x === 0;
    case "X_EQ1": return x === 1;
    case "Q_EQ0": return q === 0;
    case "Q_EQ1": return q === 1;
    case "WORLD_EQ0": return w === 0;
    case "WORLD_EQ1": return w === 1;
    default: die("bad predicate " + p);
  }
}

const INIT_TABLE = {
  C0: [0,0],
  C1: [1,1],
  X:  [0,1],
};
// index = q_before * 2 + x
const UPDATE_TABLE = {
  KEEP:          [0,0,1,1],
  CONST0:        [0,0,0,0],
  CONST1:        [1,1,1,1],
  COPY_X:        [0,1,0,1],
  NOT_Q_TABLE:   [1,1,0,0],
  ID_Q_TABLE:    [0,0,1,1],
  XOR_QX_TABLE:  [0,1,1,0],
  AND_QX_TABLE:  [0,0,0,1],
};
function initTable(init, x) {
  const row = INIT_TABLE[init];
  if (!row) die("bad tabular initial " + init);
  return row[x];
}
function updateTable(op, q, x) {
  const row = UPDATE_TABLE[op];
  if (!row) die("bad tabular update " + op);
  return row[q * 2 + x];
}
function predTable(p, w, x, q) {
  const key = [w,x,q];
  const truth = {
    X_EQ0:      [true,false,true,false,true,false,true,false],
    X_EQ1:      [false,true,false,true,false,true,false,true],
    Q_EQ0:      [true,true,false,false,true,true,false,false],
    Q_EQ1:      [false,false,true,true,false,false,true,true],
    WORLD_EQ0:  [true,true,true,true,false,false,false,false],
    WORLD_EQ1:  [false,false,false,false,true,true,true,true],
  };
  const row = truth[p];
  if (!row) die("bad tabular predicate " + p);
  return row[w * 4 + x * 2 + q];
}

function expectedTrace(desc, pt) {
  const q0a = initFormula(desc.initial_q, pt.x);
  const q1a = updateFormula(desc.update, q0a, pt.x);
  const ba = predFormula(desc.predicate, pt.w, pt.x, q1a);

  const q0b = initTable(desc.initial_q, pt.x);
  const q1b = updateTable(desc.update, q0b, pt.x);
  const bb = predTable(desc.predicate, pt.w, pt.x, q1b);

  if (q0a !== q0b || q1a !== q1b || ba !== bb) {
    die("dual reference evaluator disagreement: " + canonical({desc,pt,q0a,q0b,q1a,q1b,ba,bb}));
  }

  const terminal = EFFECTS[ba ? desc.true_trace : desc.false_trace];
  if (!terminal) die("bad terminal trace");
  return (desc.prefix === "E3" ? ["03"] : []).concat(terminal);
}

function parseArgs() {
  const a = process.argv.slice(2);
  let out = null, summary = null;
  for (let i=0;i<a.length;i++) {
    if (a[i] === "--out") out = a[++i];
    else if (a[i] === "--summary") summary = a[++i];
    else die("unknown arg " + a[i]);
  }
  if (!out || !summary) die("--out and --summary required");
  return {out, summary};
}

function inc(obj, k, n=1) { obj[k] = (obj[k] || 0) + n; }

function main() {
  const {out, summary} = parseArgs();
  const fd = fs.openSync(out, "w");
  const hash = crypto.createHash("sha256");
  const axis = {initial_q:{},update:{},predicate:{},prefix:{},true_trace:{},false_trace:{}};
  const traceLength = {};
  const payloadSequence = {};
  const branchOutcome = {true:0,false:0};
  const qAfter = {Q0:0,Q1:0};

  let index = 0;
  let pointCount = 0;
  for (const initial_q of AX.initial_q)
  for (const update of AX.update)
  for (const predicate of AX.predicate)
  for (const prefix of AX.prefix)
  for (const true_trace of AX.trace)
  for (const false_trace of AX.trace) {
    const descriptor_id = "R0-" + String(index).padStart(5, "0");
    const desc = {descriptor_id, initial_q, update, predicate, prefix, true_trace, false_trace};
    const point_traces = [];

    for (const pt of POINTS) {
      const q0 = initFormula(initial_q, pt.x);
      const q1 = updateFormula(update, q0, pt.x);
      const taken = predFormula(predicate, pt.w, pt.x, q1);
      const payloads = expectedTrace(desc, pt);
      if (!payloads.length || payloads.some(x => !["01","02","03"].includes(x))) die("bad payload trace");
      point_traces.push({
        point_symbol: pt.point_symbol,
        world_symbol: pt.world_symbol,
        x_symbol: pt.x_symbol,
        payloads,
      });
      inc(traceLength, String(payloads.length));
      inc(payloadSequence, payloads.join("-"));
      branchOutcome[taken ? "true" : "false"]++;
      qAfter[q1 ? "Q1" : "Q0"]++;
      pointCount++;
    }

    const record = {descriptor_id, initial_q, update, predicate, prefix, true_trace, false_trace, point_traces};
    const line = canonical(record) + "\n";
    fs.writeSync(fd, line);
    hash.update(line);

    inc(axis.initial_q, initial_q);
    inc(axis.update, update);
    inc(axis.predicate, predicate);
    inc(axis.prefix, prefix);
    inc(axis.true_trace, true_trace);
    inc(axis.false_trace, false_trace);
    index++;
  }
  fs.closeSync(fd);

  if (index !== 18432) die("descriptor count " + index);
  if (pointCount !== 73728) die("point count " + pointCount);

  for (const k of AX.initial_q) if (axis.initial_q[k] !== 6144) die("initial frequency " + k);
  for (const k of AX.update) if (axis.update[k] !== 2304) die("update frequency " + k);
  for (const k of AX.predicate) if (axis.predicate[k] !== 3072) die("predicate frequency " + k);
  for (const k of AX.prefix) if (axis.prefix[k] !== 9216) die("prefix frequency " + k);
  for (const k of AX.trace) {
    if (axis.true_trace[k] !== 2304) die("true trace frequency " + k);
    if (axis.false_trace[k] !== 2304) die("false trace frequency " + k);
  }

  const summaryObj = {
    reference: "risu-k1-c3-r0-w9",
    authority_created: false,
    descriptor_count: index,
    point_trace_count: pointCount,
    aggregate_digest: hash.digest("hex"),
    axis_frequencies: axis,
    trace_length_histogram: traceLength,
    payload_sequence_histogram: payloadSequence,
    branch_outcome_histogram: branchOutcome,
    q_after_update_histogram: qAfter,
    internal_dual_evaluator: "FORMULA_EQUALS_EXPLICIT_TRUTH_TABLE_FOR_ALL_73728_POINTS",
  };
  fs.writeFileSync(summary, canonical(summaryObj) + "\n");
  process.stdout.write("R0_W9_REFERENCE_PASS " + index + " " + pointCount + " " + summaryObj.aggregate_digest + "\n");
  process.stdout.write("R0_W9_TRACE_LENGTHS " + canonical(traceLength) + "\n");
  process.stdout.write("R0_W9_BRANCH_OUTCOMES " + canonical(branchOutcome) + "\n");
  process.stdout.write("R0_W9_Q_AFTER " + canonical(qAfter) + "\n");
  process.stdout.write("AUTHORITY_CREATED false\n");
}

try { main(); } catch (e) { console.error("R0_W9_REFERENCE_FAIL", e && e.stack || e); process.exit(1); }
