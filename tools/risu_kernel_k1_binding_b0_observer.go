package main

// Independent observation oracle for K1 Implementation Binding B0 D1.
//
// This program deliberately does not create K1 proof objects, does not call W1
// or W2, does not execute Python, and does not import any RISU implementation.
// It independently executes the target, observes the strict B0 effect sink,
// derives commitments, and reports only authority-relevant observation facts.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	worldIDRE = regexp.MustCompile(`^w:sha256:[0-9a-f]{64}$`)
	consIDRE  = regexp.MustCompile(`^c:sha256:[0-9a-f]{64}$`)
	claimIDRE = regexp.MustCompile(`^claim:sha256:[0-9a-f]{64}$`)
	tokenRE   = regexp.MustCompile(`^[a-z0-9._:@/-]{1,128}$`)
)

type claimDoc struct {
	Wire      string     `json:"wire"`
	Kind      string     `json:"kind"`
	Semantics string     `json:"semantics"`
	Worlds    []string   `json:"worlds"`
	Allow     [][]string `json:"allow"`
	ClaimID   string     `json:"claim_id"`
}

type pair struct {
	World       string
	Consequence string
}

type result struct {
	Observer              string   `json:"observer"`
	ObservationStatus     string   `json:"observation_status"`
	AuthorityCandidate    string   `json:"authority_candidate"`
	PreservationAuthority bool     `json:"preservation_authority"`
	WorldID               string   `json:"world_id"`
	WorldInputSHA256       string   `json:"world_input_sha256"`
	ImplementationID      string   `json:"implementation_id"`
	EffectLogSHA256       string   `json:"effect_log_sha256"`
	ObservedConsequences  []string `json:"observed_consequences"`
	ForbiddenConsequences []string `json:"forbidden_consequences"`
	TimedOut              bool     `json:"timed_out"`
	ExitCode              int      `json:"exit_code"`
	StdoutSHA256          string   `json:"stdout_sha256"`
	StderrSHA256          string   `json:"stderr_sha256"`
	Reason                 string   `json:"reason,omitempty"`
}

func netBytes(b []byte) []byte {
	return append(append([]byte(strconv.Itoa(len(b))+":"), b...), ',')
}

func netString(s string) []byte { return netBytes([]byte(s)) }

func vals(tag string, xs []string) []byte {
	var b bytes.Buffer
	b.WriteString(tag)
	b.Write(netString(strconv.Itoa(len(xs))))
	for _, x := range xs {
		b.WriteByte('V')
		b.Write(netString(x))
	}
	return b.Bytes()
}

func pairsTranscript(tag string, xs []pair) []byte {
	var b bytes.Buffer
	b.WriteString(tag)
	b.Write(netString(strconv.Itoa(len(xs))))
	for _, p := range xs {
		b.WriteByte('P')
		b.Write(netString(p.World))
		b.Write(netString(p.Consequence))
	}
	return b.Bytes()
}

func digest(prefix string, pre []byte) string {
	h := sha256.Sum256(pre)
	return prefix + hex.EncodeToString(h[:])
}

func rawSHA(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func worldID(raw []byte) string {
	pre := append([]byte("RISU-K1-BINDING-B0-WORLD\x00B"), netBytes(raw)...)
	return digest("w:sha256:", pre)
}

func consequenceID(kind, subject, value string) string {
	var b bytes.Buffer
	b.Write([]byte("RISU-K1-BINDING-B0-CONSEQUENCE\x00"))
	b.WriteByte('K')
	b.Write(netString(kind))
	b.WriteByte('S')
	b.Write(netString(subject))
	b.WriteByte('V')
	b.Write(netString(value))
	return digest("c:sha256:", b.Bytes())
}

func claimID(c claimDoc) string {
	worlds := append([]string(nil), c.Worlds...)
	sort.Strings(worlds)
	allow := make([]pair, 0, len(c.Allow))
	for _, row := range c.Allow {
		allow = append(allow, pair{World: row[0], Consequence: row[1]})
	}
	sort.Slice(allow, func(i, j int) bool {
		if allow[i].World != allow[j].World {
			return allow[i].World < allow[j].World
		}
		return allow[i].Consequence < allow[j].Consequence
	})
	var b bytes.Buffer
	b.Write([]byte("RISU-K1-CLAIM-W0\x00"))
	b.WriteByte('S')
	b.Write(netString(c.Semantics))
	b.Write(vals("W", worlds))
	b.Write(pairsTranscript("A", allow))
	return digest("claim:sha256:", b.Bytes())
}

func exactObject(raw []byte, expected []string, where string, out any) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return fmt.Errorf("%s: malformed object", where)
	}
	if len(m) != len(expected) {
		return fmt.Errorf("%s: malformed object", where)
	}
	for _, key := range expected {
		if _, ok := m[key]; !ok {
			return fmt.Errorf("%s: malformed object", where)
		}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s: malformed object", where)
	}
	return nil
}

func validateClaim(raw []byte, expectedWorld string) (claimDoc, map[string]bool, error) {
	var c claimDoc
	if err := exactObject(raw, []string{"wire", "kind", "semantics", "worlds", "allow", "claim_id"}, "claim", &c); err != nil {
		return c, nil, err
	}
	if c.Wire != "risu.k1.w0" || c.Kind != "claim" || c.Semantics != "safety-subset-v1" {
		return c, nil, errors.New("claim: unsupported wire/semantics")
	}
	if len(c.Worlds) != 1 {
		return c, nil, errors.New("claim: observer supports exactly one admitted world")
	}
	if c.Worlds[0] != expectedWorld || !worldIDRE.MatchString(c.Worlds[0]) {
		return c, nil, errors.New("claim: world commitment mismatch")
	}
	if len(c.Allow) == 0 {
		return c, nil, errors.New("claim: empty ALLOW")
	}
	allow := map[string]bool{}
	for _, row := range c.Allow {
		if len(row) != 2 || row[0] != expectedWorld || !consIDRE.MatchString(row[1]) {
			return c, nil, errors.New("claim: invalid ALLOW pair")
		}
		if allow[row[1]] {
			return c, nil, errors.New("claim: duplicate ALLOW pair")
		}
		allow[row[1]] = true
	}
	if !claimIDRE.MatchString(c.ClaimID) || c.ClaimID != claimID(c) {
		return c, nil, errors.New("claim: claim_id mismatch")
	}
	return c, allow, nil
}

func parseEffects(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return []string{}, nil
	}
	for _, ch := range raw {
		if ch > 0x7f {
			return nil, errors.New("effect sink: non-ASCII bytes")
		}
	}
	text := string(raw)
	if !strings.HasSuffix(text, "\n") {
		return nil, errors.New("effect sink: partial trailing record")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	out := make([]string, 0, len(lines))
	for i, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) != 4 || parts[0] != "E1" {
			return nil, fmt.Errorf("effect sink: malformed record %d", i)
		}
		prefixes := []string{"kind=", "subject=", "value="}
		values := make([]string, 3)
		for j := 0; j < 3; j++ {
			if !strings.HasPrefix(parts[j+1], prefixes[j]) {
				return nil, fmt.Errorf("effect sink: malformed field in record %d", i)
			}
			values[j] = strings.TrimPrefix(parts[j+1], prefixes[j])
			if !tokenRE.MatchString(values[j]) {
				return nil, fmt.Errorf("effect sink: noncanonical token in record %d", i)
			}
		}
		out = append(out, consequenceID(values[0], values[1], values[2]))
	}
	sort.Strings(out)
	uniq := out[:0]
	for _, x := range out {
		if len(uniq) == 0 || uniq[len(uniq)-1] != x {
			uniq = append(uniq, x)
		}
	}
	return uniq, nil
}

func executableSHA(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return "impl:sha256:" + rawSHA(raw), nil
}

func runTarget(executable string, worldRaw []byte, timeout time.Duration) (result, []byte, error) {
	absExe, err := filepath.Abs(executable)
	if err != nil {
		return result{}, nil, err
	}
	implID, err := executableSHA(absExe)
	if err != nil {
		return result{}, nil, err
	}
	root, err := os.MkdirTemp("", "risu-k1-b0-go-observer-")
	if err != nil {
		return result{}, nil, err
	}
	defer os.RemoveAll(root)
	worldPath := filepath.Join(root, "world.input")
	sinkDir := filepath.Join(root, "sink")
	if err := os.WriteFile(worldPath, worldRaw, 0o600); err != nil {
		return result{}, nil, err
	}
	if err := os.MkdirAll(sinkDir, 0o700); err != nil {
		return result{}, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := execCommandContext(ctx, absExe, "--world", worldPath, "--sink", sinkDir)
	cmd.Dir = root
	cmd.Env = []string{}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	} else if runErr != nil {
		exitCode = -1
	}
	effectPath := filepath.Join(sinkDir, "effects.log")
	effectRaw, readErr := os.ReadFile(effectPath)
	if os.IsNotExist(readErr) {
		effectRaw = []byte{}
	} else if readErr != nil {
		return result{}, nil, readErr
	}
	return result{
		Observer:              "risu-k1-binding-b0-observer-go-d1",
		PreservationAuthority: false,
		WorldID:               worldID(worldRaw),
		WorldInputSHA256:       rawSHA(worldRaw),
		ImplementationID:      implID,
		EffectLogSHA256:       rawSHA(effectRaw),
		TimedOut:              timedOut,
		ExitCode:              exitCode,
		StdoutSHA256:          rawSHA(stdout.Bytes()),
		StderrSHA256:          rawSHA(stderr.Bytes()),
	}, effectRaw, nil
}

// Kept behind a variable so the independence audit can verify there is no
// shell/Python path while normal Go exec remains explicit.
var execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

func main() {
	implementation := flag.String("implementation", "", "target executable")
	world := flag.String("world", "", "exact world-input file")
	claim := flag.String("claim", "", "single-world W0 claim")
	timeoutMS := flag.Int("timeout-ms", 250, "execution timeout in milliseconds")
	flag.Parse()
	if *implementation == "" || *world == "" || *claim == "" || *timeoutMS <= 0 {
		fmt.Fprintln(os.Stderr, "missing or invalid arguments")
		os.Exit(2)
	}
	worldRaw, err := os.ReadFile(*world)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	claimRaw, err := os.ReadFile(*claim)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	wid := worldID(worldRaw)
	_, allow, err := validateClaim(claimRaw, wid)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, effectRaw, err := runTarget(*implementation, worldRaw, time.Duration(*timeoutMS)*time.Millisecond)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	observed, parseErr := parseEffects(effectRaw)
	if parseErr != nil {
		out.ObservationStatus = "MALFORMED_OBSERVATION"
		out.AuthorityCandidate = "NO_AUTHORITY"
		out.ObservedConsequences = []string{}
		out.ForbiddenConsequences = []string{}
		out.Reason = parseErr.Error()
	} else {
		forbidden := make([]string, 0)
		for _, c := range observed {
			if !allow[c] {
				forbidden = append(forbidden, c)
			}
		}
		out.ObservationStatus = "OBSERVED"
		out.ObservedConsequences = observed
		out.ForbiddenConsequences = forbidden
		if len(forbidden) > 0 {
			out.AuthorityCandidate = "FORBIDDEN_OBSERVED"
		} else {
			out.AuthorityCandidate = "NO_AUTHORITY"
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
