# RISU Kernel K1 — Independent Checker W2 Qualification

**Qualification target:** `RISU_KERNEL_K1_W2_QUALIFICATION`  
**Frozen semantic base:** `k1-rc1@9e85515d4974fe06c0b1db8e94e88935381fefe5`  
**W2 implementation:** `kernel/k1_checker_w2.go`  
**Status authority:** the machine-readable qualification manifest and composite qualification verifier, not this prose document.

## 1. Why W2 exists

K1 RC1 was deliberately frozen before a second checker existed. W2 is therefore not part of the semantic definition of RC1 and does not amend it.

W2 exists to attack a different risk: a single checker can agree with its own tests because the implementation and test machinery share the same assumptions or bugs. The strongest practical response available at this stage is an independently implemented checker with a different language/runtime, followed by differential execution against a neutral corpus and independently declared oracles.

W2 is written in Go using only the Go standard library. It does not import W1, execute Python, call W1 as a subprocess, or reuse RISU checker identity/hash helpers. It independently implements the frozen W0 transcript and the `k1.finite-model/v1` checking rules.

This reduces common-mode implementation risk. It does **not** prove either checker universally correct.

## 2. Static differential D0

D0 was declared before W2 implementation and uses a neutral Python harness that imports neither checker implementation. The harness constructs wire identities independently and invokes W1 and W2 as external CLIs.

The qualification domain contains **34 vectors** covering preservation, grounded regression, open-universe target consequences, closure, grounding, totality, identity binding, byte binding, duplicates, undeclared worlds, nondeterminism, safe subsets, and ordering metamorphics.

Result on the qualified formatted W2 source:

- qualification vectors: **34/34 agreed**;
- independent oracle failures: **0**;
- W1/W2 semantic/process-class disagreements in the qualification domain: **0**;
- W2 independence audit: **PASS**;
- semantic differential equivalence: **QUALIFIED** for the declared W0-valid finite-model domain.

## 3. The disagreement was preserved, not hidden

D0 also contains parser-boundary sentinels outside the W0-valid qualification domain.

One sentinel intentionally uses a proof-kind string that violates the W0 lexical pattern. W1 currently accepts the string structurally and later returns `UNSUPPORTED/UNKNOWN`; W2 enforces the lexical pattern earlier and returns `REJECTED/NONE`.

This is classified as:

`FAIL_CLOSED_STRUCTURAL_DIVERGENCE`

Both implementations refuse semantic authority. There is no preservation or regression claim created by the disagreement. Nevertheless, the implementations are **not** claimed to have full wire-parser equivalence.

Accordingly:

- semantic differential equivalence over the declared valid domain: **QUALIFIED**;
- full wire-parser equivalence: **NOT QUALIFIED**.

W1 was not changed to make the comparison prettier because W1 is part of frozen RC1 evidence. W2 was not weakened to imitate W1's parser behavior.

## 4. Seeded generative differential D1

A finite hand-written corpus can miss common-mode transcript or cardinality mistakes. D1 was therefore precommitted before its generator implementation.

D1 uses deterministic seed `1261524786` and executes **64 trials × 6 properties = 384 comparisons**. Each trial generates 1–5 worlds, 1–4 allowed consequences per world, and variable evidence roots, then tests:

1. a total safe subset preservation certificate;
2. a fresh target-native forbidden witness;
3. the same forbidden relation incorrectly submitted as a preservation certificate;
4. semantic permutation invariance;
5. proof-artifact byte tampering;
6. grounding omission.

Result:

- comparisons: **384/384 agreed**;
- oracle failures: **0**;
- semantic identity failures: **0**;
- W1/W2 disagreements: **0**;
- claim/target permutation invariance: **PASS**.

The generator imports neither checker implementation and invokes both externally.

## 5. Source and build hygiene

The qualified W2 source is required to be:

- `gofmt` canonical;
- `go vet` clean;
- built with `CGO_ENABLED=0`;
- compiled with the Go standard library only;
- free of W1 imports, Python execution, shared RISU checker helpers, and W1 subprocess calls.

A source-byte change invalidates its pinned Git blob and requires requalification.

## 6. RC1 isolation

The composite qualification verifier requires the exact RC1 commit to be an ancestor of the qualification head and requires every diff entry relative to RC1 to have Git status `A`.

Therefore no file already present in RC1 may be modified, deleted, or renamed by this qualification branch. W2 and its evidence are additive corroboration only.

## 7. Exact claim justified by this work

The strongest justified statement is:

> For the frozen K1 RC1 W0 + `k1.finite-model/v1` fragment, an independently implemented Go checker and the frozen Python W1 checker produce the same semantic/process class on all 34 declared static qualification vectors and all 384 precommitted seeded generative comparisons, with zero independent-oracle failures. One fail-closed parser-boundary disagreement is explicitly retained and prevents any claim of full wire-parser equivalence.

This supports the K1 semantic narrow waist by reducing dependence on one checker implementation.

It does **not** establish:

- universal checker correctness;
- full wire-parser equivalence;
- implementation binding;
- correctness outside the declared finite-model proof fragment;
- unbounded liveness;
- that two agreeing implementations cannot share a specification-level mistake.

## 8. What should come next

The next high-leverage problem is no longer another same-fragment checker. After W2 qualification is frozen, the strongest next step is to attack **implementation binding**: establish a proof/evidence lane that connects a declared finite target model or local regression witness to real implementation behavior without enlarging the K1 semantic primitive set unless falsification forces it.

The qualified W1/W2 pair should then serve as independent consumers of that proof lane, rather than becoming a reason to add more semantic machinery to K1.
