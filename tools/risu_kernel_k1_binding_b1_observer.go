package main

// Independent B1 D2 observer. It executes the target itself, reads only the
// fresh effect sink, and independently derives world/implementation/consequence
// commitments plus the first forbidden record. It invokes no RISU checker and
// executes no Python.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var worldDomain = []byte("RISU-K1-BINDING-B0-WORLD\x00")
var consequenceDomain = []byte("RISU-K1-BINDING-B0-CONSEQUENCE\x00")
var tokenRE = regexp.MustCompile(`^[a-z0-9._:@/-]{1,128}$`)

type Claim struct {
	Worlds  []string   `json:"worlds"`
	Allow   [][]string `json:"allow"`
	ClaimID string     `json:"claim_id"`
}

type Pair struct{ W, C string }

type Output struct {
	Observer              string   `json:"observer"`
	ObservationStatus     string   `json:"observation_status"`
	AuthorityCandidate    string   `json:"authority_candidate"`
	PreservationAuthority bool     `json:"preservation_authority"`
	ClaimID               string   `json:"claim_id"`
	WorldID               string   `json:"world_id"`
	ImplementationID      string   `json:"implementation_id"`
	ObservedConsequences  []string `json:"observed_consequences"`
	FirstForbiddenPair    []string `json:"first_forbidden_pair"`
	FirstForbiddenIndex   *int     `json:"first_forbidden_index"`
	TimedOut              bool     `json:"timed_out"`
	ExitCode              *int     `json:"exit_code"`
	EffectLogSHA256       string   `json:"effect_log_sha256"`
	StdoutSHA256          string   `json:"stdout_sha256"`
	StderrSHA256          string   `json:"stderr_sha256"`
	Reason                string   `json:"reason,omitempty"`
}

func netBytes(raw []byte) []byte {
	out := []byte(strconv.Itoa(len(raw)) + ":")
	out = append(out, raw...)
	return append(out, ',')
}
func net(s string) []byte { return netBytes([]byte(s)) }
func digest(prefix string, raw []byte) string { h := sha256.Sum256(raw); return prefix + hex.EncodeToString(h[:]) }
func hashHex(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func worldID(raw []byte) string {
	var b bytes.Buffer
	b.Write(worldDomain)
	b.WriteByte('B')
	b.Write(netBytes(raw))
	return digest("w:sha256:", b.Bytes())
}
func consequenceID(kind, subject, value string) string {
	var b bytes.Buffer
	b.Write(consequenceDomain)
	b.WriteByte('K')
	b.Write(net(kind))
	b.WriteByte('S')
	b.Write(net(subject))
	b.WriteByte('V')
	b.Write(net(value))
	return digest("c:sha256:", b.Bytes())
}

func parseEffect(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return []string{}, nil
	}
	for _, c := range raw {
		if c > 0x7f {
			return nil, fmt.Errorf("non-ASCII effect sink")
		}
	}
	if !bytes.HasSuffix(raw, []byte("\n")) {
		return nil, fmt.Errorf("partial trailing record")
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	out := make([]string, 0, len(lines))
	for i, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) != 4 || parts[0] != "E1" {
			return nil, fmt.Errorf("record %d malformed", i)
		}
		prefixes := []string{"kind=", "subject=", "value="}
		values := make([]string, 3)
		for j := 0; j < 3; j++ {
			if !strings.HasPrefix(parts[j+1], prefixes[j]) {
				return nil, fmt.Errorf("record %d field malformed", i)
			}
			values[j] = strings.TrimPrefix(parts[j+1], prefixes[j])
			if !tokenRE.MatchString(values[j]) {
				return nil, fmt.Errorf("record %d token noncanonical", i)
			}
		}
		out = append(out, consequenceID(values[0], values[1], values[2]))
	}
	return out, nil
}

func execute(binary string, worldRaw []byte, timeout time.Duration) (effectRaw, stdout, stderr []byte, timedOut bool, exitCode *int, err error) {
	root, err := os.MkdirTemp("", "risu-b1-d2-")
	if err != nil { return nil, nil, nil, false, nil, err }
	defer os.RemoveAll(root)
	worldPath := filepath.Join(root, "world.input")
	sink := filepath.Join(root, "sink")
	if err := os.WriteFile(worldPath, worldRaw, 0o600); err != nil { return nil,nil,nil,false,nil,err }
	if err := os.Mkdir(sink, 0o700); err != nil { return nil,nil,nil,false,nil,err }
	entries, err := os.ReadDir(sink); if err != nil || len(entries) != 0 { return nil,nil,nil,false,nil,fmt.Errorf("sink not empty") }
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--world", worldPath, "--sink", sink)
	cmd.Dir = root
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf; cmd.Stderr = &errBuf
	runErr := cmd.Run()
	timedOut = ctx.Err() == context.DeadlineExceeded
	if cmd.ProcessState != nil {
		code := cmd.ProcessState.ExitCode()
		exitCode = &code
	}
	if runErr != nil && cmd.ProcessState == nil && !timedOut { return nil,nil,nil,timedOut,exitCode,runErr }
	effectPath := filepath.Join(sink, "effects.log")
	effectRaw, readErr := os.ReadFile(effectPath)
	if os.IsNotExist(readErr) { effectRaw = []byte{} } else if readErr != nil { return nil,nil,nil,timedOut,exitCode,readErr }
	entries, err = os.ReadDir(sink); if err != nil { return nil,nil,nil,timedOut,exitCode,err }
	for _, e := range entries { if e.Name() != "effects.log" { return nil,nil,nil,timedOut,exitCode,fmt.Errorf("unexpected sink entry") } }
	return effectRaw, outBuf.Bytes(), errBuf.Bytes(), timedOut, exitCode, nil
}

func main() {
	claimPath := flag.String("claim", "", "claim")
	worldPath := flag.String("world", "", "selected exact world bytes")
	implementation := flag.String("implementation", "", "exact executable")
	timeoutMS := flag.Int("timeout-ms", 250, "timeout milliseconds")
	flag.Parse()
	if *claimPath == "" || *worldPath == "" || *implementation == "" || *timeoutMS <= 0 { os.Exit(64) }
	claimRaw, err := os.ReadFile(*claimPath); if err != nil { os.Exit(65) }
	var claim Claim; if err := json.Unmarshal(claimRaw, &claim); err != nil { os.Exit(65) }
	worldRaw, err := os.ReadFile(*worldPath); if err != nil { os.Exit(65) }
	implRaw, err := os.ReadFile(*implementation); if err != nil { os.Exit(65) }
	wid := worldID(worldRaw)
	declared := false
	for _, w := range claim.Worlds { if w == wid { declared = true } }
	if !declared { os.Exit(66) }
	allow := map[Pair]bool{}
	for _, row := range claim.Allow { if len(row) == 2 { allow[Pair{row[0], row[1]}] = true } }
	effectRaw, stdout, stderr, timedOut, exitCode, err := execute(*implementation, worldRaw, time.Duration(*timeoutMS)*time.Millisecond)
	if err != nil { os.Exit(70) }
	result := Output{
		Observer: "risu-k1-binding-b1-observer-go-d2", ObservationStatus: "OBSERVED",
		AuthorityCandidate: "NO_AUTHORITY", PreservationAuthority: false, ClaimID: claim.ClaimID,
		WorldID: wid, ImplementationID: digest("impl:sha256:", implRaw),
		ObservedConsequences: []string{}, FirstForbiddenPair: nil, FirstForbiddenIndex: nil,
		TimedOut: timedOut, ExitCode: exitCode, EffectLogSHA256: hashHex(effectRaw),
		StdoutSHA256: hashHex(stdout), StderrSHA256: hashHex(stderr),
	}
	consequences, parseErr := parseEffect(effectRaw)
	if parseErr != nil {
		result.ObservationStatus = "MALFORMED_OBSERVATION"
		result.Reason = parseErr.Error()
	} else {
		result.ObservedConsequences = consequences
		for i, c := range consequences {
			if !allow[Pair{wid, c}] {
				idx := i
				result.FirstForbiddenIndex = &idx
				result.FirstForbiddenPair = []string{wid, c}
				result.AuthorityCandidate = "FORBIDDEN_OBSERVED"
				break
			}
		}
	}
	// Stable JSON output; sort is intentionally used only for a deterministic no-op
	// sanity check so imported sort remains part of the explicit standard-library surface.
	copyConsequences := append([]string(nil), result.ObservedConsequences...)
	sort.Strings(copyConsequences)
	_ = copyConsequences
	enc := json.NewEncoder(os.Stdout); enc.SetIndent("", "  "); _ = enc.Encode(result)
}
