package main

// Independent observation oracle for K1 Implementation Binding B0 D1.
// It creates no K1 proof object, invokes no checker, executes no Python, and
// shares no helper code with the Python binder.

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
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	worldRE = regexp.MustCompile(`^w:sha256:[0-9a-f]{64}$`)
	consRE  = regexp.MustCompile(`^c:sha256:[0-9a-f]{64}$`)
	claimRE = regexp.MustCompile(`^claim:sha256:[0-9a-f]{64}$`)
	tokenRE = regexp.MustCompile(`^[a-z0-9._:@/-]{1,128}$`)
)

type claim struct {
	Wire      string     `json:"wire"`
	Kind      string     `json:"kind"`
	Semantics string     `json:"semantics"`
	Worlds    []string   `json:"worlds"`
	Allow     [][]string `json:"allow"`
	ClaimID   string     `json:"claim_id"`
}

type pair struct{ w, c string }

type observation struct {
	Observer              string   `json:"observer"`
	ObservationStatus     string   `json:"observation_status"`
	AuthorityCandidate    string   `json:"authority_candidate"`
	PreservationAuthority bool     `json:"preservation_authority"`
	WorldID               string   `json:"world_id"`
	WorldInputSHA256      string   `json:"world_input_sha256"`
	ImplementationID      string   `json:"implementation_id"`
	EffectLogSHA256       string   `json:"effect_log_sha256"`
	ObservedConsequences  []string `json:"observed_consequences"`
	ForbiddenConsequences []string `json:"forbidden_consequences"`
	TimedOut              bool     `json:"timed_out"`
	ExitCode              int      `json:"exit_code"`
	StdoutSHA256          string   `json:"stdout_sha256"`
	StderrSHA256          string   `json:"stderr_sha256"`
	Reason                string   `json:"reason,omitempty"`
}

func hashHex(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func digest(prefix string, raw []byte) string { return prefix + hashHex(raw) }

func netBytes(raw []byte) []byte {
	out := []byte(strconv.Itoa(len(raw)) + ":")
	out = append(out, raw...)
	return append(out, ',')
}

func netString(s string) []byte { return netBytes([]byte(s)) }

func values(tag string, xs []string) []byte {
	var b bytes.Buffer
	b.WriteString(tag)
	b.Write(netString(strconv.Itoa(len(xs))))
	for _, x := range xs {
		b.WriteByte('V')
		b.Write(netString(x))
	}
	return b.Bytes()
}

func relation(tag string, xs []pair) []byte {
	var b bytes.Buffer
	b.WriteString(tag)
	b.Write(netString(strconv.Itoa(len(xs))))
	for _, p := range xs {
		b.WriteByte('P')
		b.Write(netString(p.w))
		b.Write(netString(p.c))
	}
	return b.Bytes()
}

func worldID(raw []byte) string {
	pre := []byte("RISU-K1-BINDING-B0-WORLD\x00B")
	pre = append(pre, netBytes(raw)...)
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

func computedClaimID(c claim) string {
	worlds := append([]string(nil), c.Worlds...)
	sort.Strings(worlds)
	allow := make([]pair, 0, len(c.Allow))
	for _, row := range c.Allow {
		allow = append(allow, pair{row[0], row[1]})
	}
	sort.Slice(allow, func(i, j int) bool {
		if allow[i].w != allow[j].w {
			return allow[i].w < allow[j].w
		}
		return allow[i].c < allow[j].c
	})
	var b bytes.Buffer
	b.Write([]byte("RISU-K1-CLAIM-W0\x00"))
	b.WriteByte('S')
	b.Write(netString(c.Semantics))
	b.Write(values("W", worlds))
	b.Write(relation("A", allow))
	return digest("claim:sha256:", b.Bytes())
}

func decodeClaim(raw []byte, expectedWorld string) (map[string]bool, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return nil, errors.New("claim: malformed object")
	}
	expected := []string{"wire", "kind", "semantics", "worlds", "allow", "claim_id"}
	if len(top) != len(expected) {
		return nil, errors.New("claim: malformed object")
	}
	for _, key := range expected {
		if _, ok := top[key]; !ok {
			return nil, errors.New("claim: malformed object")
		}
	}
	var c claim
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("claim: malformed object")
	}
	if c.Wire != "risu.k1.w0" || c.Kind != "claim" || c.Semantics != "safety-subset-v1" {
		return nil, errors.New("claim: unsupported wire/semantics")
	}
	if len(c.Worlds) != 1 || c.Worlds[0] != expectedWorld || !worldRE.MatchString(c.Worlds[0]) {
		return nil, errors.New("claim: single-world commitment mismatch")
	}
	if len(c.Allow) == 0 {
		return nil, errors.New("claim: empty ALLOW")
	}
	allow := map[string]bool{}
	for _, row := range c.Allow {
		if len(row) != 2 || row[0] != expectedWorld || !consRE.MatchString(row[1]) || allow[row[1]] {
			return nil, errors.New("claim: invalid ALLOW")
		}
		allow[row[1]] = true
	}
	if !claimRE.MatchString(c.ClaimID) || c.ClaimID != computedClaimID(c) {
		return nil, errors.New("claim: claim_id mismatch")
	}
	return allow, nil
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
	ids := make([]string, 0, len(lines))
	for i, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) != 4 || parts[0] != "E1" {
			return nil, fmt.Errorf("effect sink: malformed record %d", i)
		}
		prefix := []string{"kind=", "subject=", "value="}
		v := make([]string, 3)
		for j := 0; j < 3; j++ {
			if !strings.HasPrefix(parts[j+1], prefix[j]) {
				return nil, fmt.Errorf("effect sink: malformed field in record %d", i)
			}
			v[j] = strings.TrimPrefix(parts[j+1], prefix[j])
			if !tokenRE.MatchString(v[j]) {
				return nil, fmt.Errorf("effect sink: noncanonical token in record %d", i)
			}
		}
		ids = append(ids, consequenceID(v[0], v[1], v[2]))
	}
	sort.Strings(ids)
	uniq := make([]string, 0, len(ids))
	for _, id := range ids {
		if len(uniq) == 0 || uniq[len(uniq)-1] != id {
			uniq = append(uniq, id)
		}
	}
	return uniq, nil
}

func executableID(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return "impl:sha256:" + hashHex(raw), nil
}

func observe(executable string, worldRaw []byte, timeout time.Duration) (observation, []byte, error) {
	absExe, err := filepath.Abs(executable)
	if err != nil {
		return observation{}, nil, err
	}
	implID, err := executableID(absExe)
	if err != nil {
		return observation{}, nil, err
	}
	root, err := os.MkdirTemp("", "risu-k1-b0-observer-")
	if err != nil {
		return observation{}, nil, err
	}
	defer os.RemoveAll(root)
	worldPath := filepath.Join(root, "world.input")
	sinkDir := filepath.Join(root, "sink")
	if err := os.WriteFile(worldPath, worldRaw, 0o600); err != nil {
		return observation{}, nil, err
	}
	if err := os.MkdirAll(sinkDir, 0o700); err != nil {
		return observation{}, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, absExe, "--world", worldPath, "--sink", sinkDir)
	cmd.Dir = root
	cmd.Env = []string{}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	} else if runErr != nil {
		exitCode = -1
	}
	effectRaw, err := os.ReadFile(filepath.Join(sinkDir, "effects.log"))
	if os.IsNotExist(err) {
		effectRaw = []byte{}
	} else if err != nil {
		return observation{}, nil, err
	}
	return observation{
		Observer:              "risu-k1-binding-b0-observer-go-d1",
		PreservationAuthority: false,
		WorldID:               worldID(worldRaw),
		WorldInputSHA256:      hashHex(worldRaw),
		ImplementationID:      implID,
		EffectLogSHA256:       hashHex(effectRaw),
		TimedOut:              timedOut,
		ExitCode:              exitCode,
		StdoutSHA256:          hashHex(stdout.Bytes()),
		StderrSHA256:          hashHex(stderr.Bytes()),
	}, effectRaw, nil
}

func main() {
	implementation := flag.String("implementation", "", "target executable")
	worldPath := flag.String("world", "", "exact world-input file")
	claimPath := flag.String("claim", "", "single-world W0 claim")
	timeoutMS := flag.Int("timeout-ms", 250, "execution timeout milliseconds")
	flag.Parse()
	if *implementation == "" || *worldPath == "" || *claimPath == "" || *timeoutMS <= 0 {
		fmt.Fprintln(os.Stderr, "missing or invalid arguments")
		os.Exit(2)
	}
	worldRaw, err := os.ReadFile(*worldPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	claimRaw, err := os.ReadFile(*claimPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	wid := worldID(worldRaw)
	allow, err := decodeClaim(claimRaw, wid)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, effectRaw, err := observe(*implementation, worldRaw, time.Duration(*timeoutMS)*time.Millisecond)
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
		for _, id := range observed {
			if !allow[id] {
				forbidden = append(forbidden, id)
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
