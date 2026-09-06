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

func project(sourceIntent Intent) Request {
    return Request{Payload: sourceIntent.Payload, GuardMark: sourceIntent.GuardMark}
}

func targetApply(currentMark string, req Request) Observation {
    // Effect cut: the consequential write is reachable only when the carried mark matches.
    if req.GuardMark != currentMark {
        return Observation{Outcome: "STALE_REJECTED_NO_EFFECT", Effect: false}
    }
    return Observation{Outcome: "WRITE_APPLIED", Effect: true}
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
