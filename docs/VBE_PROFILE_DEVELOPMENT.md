# Version-Bound Effect Profile — Development Record

## Why this profile exists

Cases 001, 002, and 003 repeatedly instantiate the same consequence shape despite different carriers: a consequential effect is authorized relative to a reviewed version and the effect-time current version may diverge before execution. The development profile extracts that recurring shape without moving carrier-specific evidence or verdict authority into the profile layer.

## Architecture

```text
VBE semantic instance                 carrier evidence envelope
(reviewed/current/effect semantics)   (bytes, facts, provenance)
             \                         /
              \                       /
               v                     v
                 vbe_compile.py
                       |
                       v
       Source Consequence Contract + target semantic program
                       |
              frozen v0.7 producer
                       |
              independent consumer
```

`vbe_compile.py` is untrusted convenience code. It may construct artifacts but may not establish C, D, O, Exact Realization, or a product status.

## Calibration result

Four calibration cells are retained:

1. GitHub guarded merge — omitted reviewed-version guard — `CONSEQUENCE_REGRESSION`, C1/D1/O0.
2. Azure DevOps wiki edit — preserved reviewed ETag binding — `PRESERVED`, C1/D1/O1.
3. GitHub file update before #2134 — wrong validator semantic space — `CONSEQUENCE_REGRESSION`, C0/D-NA/O-NA.
4. GitHub file update after #2134 — preserved blob-SHA comparison — `PRESERVED`, C1/D1/O1.

For each cell, the profile-compiled artifact must match the retained legacy artifact on source semantic digest, bounded world/consequence rows, C/D/O, structural classification/coverage, Exact status/failure mode, and product status. The current differential record is `results/VBE_CALIBRATION_DIFFERENTIAL.json`.

## What the calibration does not prove

It does not prove the profile generalizes to unseen systems. The calibration cases were used to extract the profile. Generalization begins only with prospectively selected Corpus 0.1 units after the external timestamp gate opens.
