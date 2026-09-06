package main

import (
    "encoding/json"
    "fmt"
)

type Intent struct {
    Payload   string
    GuardMark string
}

type Request struct {
    Payload   string
    GuardMark string
}

type Observation struct {
    Outcome string `json:"outcome"`
    Effect  bool   `json:"effect"`
}

func project(intent Intent) Request {
    return Request{Payload: intent.Payload, GuardMark: intent.GuardMark}
}

func targetApply(currentMark string, req Request) Observation {
    applied := Observation{Outcome: "WRITE_APPLIED", Effect: true} // MUTATION P06: effect first.
    if req.GuardMark != currentMark {
        return applied
    }
    return applied
}

func execute(currentMark, suppliedMark string) Observation {
    return targetApply(currentMark, project(Intent{Payload: "v1", GuardMark: suppliedMark}))
}

func main() {
    observations := map[string]Observation{
        "W_MATCH": execute("m0", "m0"),
        "W_STALE": execute("m1", "m0"),
    }
    b, err := json.Marshal(observations)
    if err != nil {
        panic(err)
    }
    fmt.Println(string(b))
}
