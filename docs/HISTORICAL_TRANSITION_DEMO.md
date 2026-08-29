# Historical transition demo

Run the two revisions independently:

```sh
set +e
./risu-verify verify cases/github-create-update-sha-transition/before
before_rc=$?
set -e
[ "$before_rc" -eq 10 ]

./risu-verify verify cases/github-create-update-sha-transition/after
```

Then derive the pair record:

```sh
python tools/historical_transition.py cases/github-create-update-sha-transition --json
```

Expected directional result for the sealed Case 003 record:

```text
BEFORE  CONSEQUENCE_REGRESSION  C0/D-NA/O-NA  REALIZATION_CONTRADICTED
AFTER   PRESERVED               C1/D1/O1      REALIZATION_ESTABLISHED
PAIR    REPAIR_CONSISTENT_HISTORICAL_TRANSITION
```

The expected result is a frozen qualification artifact after the first sealed run; it was not part of the predeclaration.
