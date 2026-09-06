package main

import (
    "encoding/json"
    "fmt"
)

type Snapshot struct {
    Epoch int
}

type Command struct {
    Body          string
    ExpectedEpoch int
}

type Observation struct {
    Outcome string `json:"outcome"`
    Effect  bool   `json:"effect"`
}

func readSnapshot(currentEpoch int) Snapshot {
    return Snapshot{Epoch: currentEpoch}
}

func buildCommand(body string, suppliedEpoch int) Command {
    return Command{Body: body, ExpectedEpoch: suppliedEpoch}
}

func guardedCommit(snapshot Snapshot, command Command) Observation {
    // Effect cut: the effect is control-dependent on the comparison result.
    if snapshot.Epoch != command.ExpectedEpoch {
        return Observation{Outcome: "STALE_REJECTED_NO_EFFECT", Effect: false}
    }
    return Observation{Outcome: "WRITE_APPLIED", Effect: true}
}

func execute(currentEpoch, suppliedEpoch int) Observation {
    snapshot := readSnapshot(currentEpoch)
    command := buildCommand("v1", suppliedEpoch)
    otherResource := Snapshot{Epoch: currentEpoch} // MUTATION P04: wrong resource coordinate.
    command.ExpectedEpoch = otherResource.Epoch
    return guardedCommit(snapshot, command)
}

func main() {
    observations := map[string]Observation{
        "W_MATCH": execute(21, 21),
        "W_STALE": execute(22, 21),
    }
    b, err := json.Marshal(observations)
    if err != nil {
        panic(err)
    }
    fmt.Println(string(b))
}
