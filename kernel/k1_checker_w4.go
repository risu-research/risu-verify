package main

// K1 checker W4 independently corroborates k1.observed-pair/v1 regression
// witnesses. It uses only the Go standard library, executes no Python, imports
// no RISU checker code, and has zero preservation authority.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const proofKind = "k1.observed-pair/v1"
const profile = "risu.binding.effect-sink-e1/v1"

var worldDomain = []byte("RISU-K1-BINDING-B0-WORLD\x00")
var consequenceDomain = []byte("RISU-K1-BINDING-B0-CONSEQUENCE\x00")
var targetDomain = []byte("RISU-K1-TARGET-OBSERVED-PAIR-V1\x00")
var tokenRE = regexp.MustCompile(`^[a-z0-9._:@/-]{1,128}$`)
var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var idRE = map[string]*regexp.Regexp{
	"w":     regexp.MustCompile(`^w:sha256:[0-9a-f]{64}$`),
	"c":     regexp.MustCompile(`^c:sha256:[0-9a-f]{64}$`),
	"t":     regexp.MustCompile(`^t:sha256:[0-9a-f]{64}$`),
	"p":     regexp.MustCompile(`^p:sha256:[0-9a-f]{64}$`),
	"e":     regexp.MustCompile(`^e:sha256:[0-9a-f]{64}$`),
	"claim": regexp.MustCompile(`^claim:sha256:[0-9a-f]{64}$`),
	"wit":   regexp.MustCompile(`^wit:sha256:[0-9a-f]{64}$`),
	"impl":  regexp.MustCompile(`^impl:sha256:[0-9a-f]{64}$`),
}

type rejectError struct{ msg string }

func (e rejectError) Error() string { return e.msg }

type unsupportedError struct{ msg string }

func (e unsupportedError) Error() string { return e.msg }
func reject(s string) error              { return rejectError{s} }
func unsupported(s string) error         { return unsupportedError{s} }

type Pair struct{ W, C string }
type ProofRef struct {
	Kind     string `json:"kind"`
	Artifact string `json:"artifact"`
}
type Claim struct {
	Wire      string     `json:"wire"`
	Kind      string     `json:"kind"`
	Semantics string     `json:"semantics"`
	Worlds    []string   `json:"worlds"`
	Allow     [][]string `json:"allow"`
	ClaimID   string     `json:"claim_id"`
}
type Witness struct {
	Wire           string    `json:"wire"`
	Kind           string    `json:"kind"`
	ClaimID        string    `json:"claim_id"`
	TargetID       string    `json:"target_id"`
	Pair           [2]string `json:"pair"`
	GroundingProof ProofRef  `json:"grounding_proof"`
	EvidenceRoots  []string  `json:"evidence_roots"`
	WitnessID      string    `json:"witness_id"`
}
type Artifact struct {
	ProofFormat      string    `json:"proof_format"`
	Profile          string    `json:"profile"`
	ClaimID          string    `json:"claim_id"`
	TargetID         string    `json:"target_id"`
	Pair             [2]string `json:"pair"`
	ImplementationID string    `json:"implementation_id"`
	WorldInputB64    string    `json:"world_input_b64"`
	EffectLogB64     string    `json:"effect_log_b64"`
	RecordIndex      int       `json:"record_index"`
	TimedOut         bool      `json:"timed_out"`
	ExitCode         *int      `json:"exit_code"`
	StdoutSHA256     string    `json:"stdout_sha256"`
	StderrSHA256     string    `json:"stderr_sha256"`
}

type Result map[string]any

func netBytes(b []byte) []byte { return append(append([]byte(strconv.Itoa(len(b))+":"), b...), ',') }
func net(s string) []byte      { return netBytes([]byte(s)) }
func vals(tag string, xs []string) []byte {
	var b bytes.Buffer
	b.WriteString(tag)
	b.Write(net(strconv.Itoa(len(xs))))
	for _, x := range xs {
		b.WriteByte('V')
		b.Write(net(x))
	}
	return b.Bytes()
}
func pairsTranscript(tag string, xs []Pair) []byte {
	var b bytes.Buffer
	b.WriteString(tag)
	b.Write(net(strconv.Itoa(len(xs))))
	for _, p := range xs {
		b.WriteByte('P')
		b.Write(net(p.W))
		b.Write(net(p.C))
	}
	return b.Bytes()
}
func digest(prefix string, raw []byte) string {
	h := sha256.Sum256(raw)
	return prefix + hex.EncodeToString(h[:])
}
func ident(kind, value, where string) error {
	if r := idRE[kind]; r == nil || !r.MatchString(value) {
		return reject(where + ": noncanonical identifier")
	}
	return nil
}

func exact(raw []byte, keys []string, where string, out any) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil || len(m) != len(keys) {
		return reject(where + ": malformed object")
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return reject(where + ": malformed object")
		}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return reject(where + ": malformed object")
	}
	return nil
}

func parsePair(row []string, where string) (Pair, error) {
	var p Pair
	if len(row) != 2 {
		return p, reject(where + ": expected pair")
	}
	if err := ident("w", row[0], where+".world"); err != nil {
		return p, err
	}
	if err := ident("c", row[1], where+".consequence"); err != nil {
		return p, err
	}
	return Pair{row[0], row[1]}, nil
}
func parseRelation(rows [][]string, where string) ([]Pair, error) {
	out := []Pair{}
	seen := map[Pair]bool{}
	for i, row := range rows {
		p, err := parsePair(row, fmt.Sprintf("%s[%d]", where, i))
		if err != nil {
			return nil, err
		}
		if seen[p] {
			return nil, reject(where + ": duplicate pair")
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}
func pairLess(a, b Pair) bool {
	if a.W != b.W {
		return a.W < b.W
	}
	return a.C < b.C
}
func sortedPairs(xs []Pair) []Pair {
	out := append([]Pair(nil), xs...)
	sort.Slice(out, func(i, j int) bool { return pairLess(out[i], out[j]) })
	return out
}

func claimID(c Claim, allow []Pair) string {
	ws := append([]string(nil), c.Worlds...)
	sort.Strings(ws)
	as := sortedPairs(allow)
	var b bytes.Buffer
	b.Write([]byte("RISU-K1-CLAIM-W0\x00"))
	b.WriteByte('S')
	b.Write(net(c.Semantics))
	b.Write(vals("W", ws))
	b.Write(pairsTranscript("A", as))
	return digest("claim:sha256:", b.Bytes())
}
func witnessID(w Witness) string {
	roots := append([]string(nil), w.EvidenceRoots...)
	sort.Strings(roots)
	var b bytes.Buffer
	b.Write([]byte("RISU-K1-WIT-W0\x00"))
	b.WriteByte('C')
	b.Write(net(w.ClaimID))
	b.WriteByte('T')
	b.Write(net(w.TargetID))
	b.WriteByte('P')
	b.Write(net(w.Pair[0]))
	b.Write(net(w.Pair[1]))
	b.WriteByte('G')
	b.Write(net(w.GroundingProof.Kind))
	b.Write(net(w.GroundingProof.Artifact))
	b.Write(vals("E", roots))
	return digest("wit:sha256:", b.Bytes())
}
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

func canonicalB64(s, where string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, reject(where + ": invalid base64")
	}
	if base64.StdEncoding.EncodeToString(raw) != s {
		return nil, reject(where + ": noncanonical base64")
	}
	return raw, nil
}
func parseEffect(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return []string{}, nil
	}
	if !bytes.HasSuffix(raw, []byte("\n")) {
		return nil, reject("artifact.effect_log: partial trailing record")
	}
	text := string(raw)
	if !utf8ASCII(raw) {
		return nil, reject("artifact.effect_log: non-ASCII bytes")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	out := []string{}
	for i, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) != 4 || parts[0] != "E1" {
			return nil, reject(fmt.Sprintf("artifact.effect_log[%d]: malformed record", i))
		}
		prefixes := []string{"kind=", "subject=", "value="}
		vals := []string{}
		for j := 0; j < 3; j++ {
			if !strings.HasPrefix(parts[j+1], prefixes[j]) {
				return nil, reject(fmt.Sprintf("artifact.effect_log[%d]: malformed field", i))
			}
			v := strings.TrimPrefix(parts[j+1], prefixes[j])
			if !tokenRE.MatchString(v) {
				return nil, reject(fmt.Sprintf("artifact.effect_log[%d]: noncanonical token", i))
			}
			vals = append(vals, v)
		}
		out = append(out, consequenceID(vals[0], vals[1], vals[2]))
	}
	return out, nil
}
func utf8ASCII(raw []byte) bool {
	for _, b := range raw {
		if b > 0x7f {
			return false
		}
	}
	return true
}

func targetID(a Artifact, worldRaw, effectRaw []byte) string {
	exitToken := "null"
	if a.ExitCode != nil {
		exitToken = strconv.Itoa(*a.ExitCode)
	}
	wh := sha256.Sum256(worldRaw)
	eh := sha256.Sum256(effectRaw)
	fields := [][2]string{{"P", a.Profile}, {"C", a.ClaimID}, {"W", a.Pair[0]}, {"U", a.Pair[1]}, {"I", a.ImplementationID}, {"H", hex.EncodeToString(wh[:])}, {"L", hex.EncodeToString(eh[:])}, {"N", strconv.Itoa(a.RecordIndex)}, {"O", map[bool]string{true: "1", false: "0"}[a.TimedOut]}, {"X", exitToken}, {"S", a.StdoutSHA256}, {"E", a.StderrSHA256}}
	var b bytes.Buffer
	b.Write(targetDomain)
	for _, f := range fields {
		b.WriteString(f[0])
		b.Write(net(f[1]))
	}
	return digest("t:sha256:", b.Bytes())
}

func checkClaim(raw []byte) (Claim, []Pair, map[string]bool, error) {
	var c Claim
	if err := exact(raw, []string{"wire", "kind", "semantics", "worlds", "allow", "claim_id"}, "claim", &c); err != nil {
		return c, nil, nil, err
	}
	if c.Wire != "risu.k1.w0" || c.Kind != "claim" || c.Semantics != "safety-subset-v1" {
		return c, nil, nil, reject("claim: unsupported wire/semantics")
	}
	if len(c.Worlds) == 0 {
		return c, nil, nil, reject("claim.worlds: empty")
	}
	worlds := map[string]bool{}
	for _, w := range c.Worlds {
		if err := ident("w", w, "claim.world"); err != nil {
			return c, nil, nil, err
		}
		if worlds[w] {
			return c, nil, nil, reject("claim.worlds: duplicate")
		}
		worlds[w] = true
	}
	allow, err := parseRelation(c.Allow, "claim.allow")
	if err != nil {
		return c, nil, nil, err
	}
	if len(allow) == 0 {
		return c, nil, nil, reject("claim.allow: empty")
	}
	has := map[string]bool{}
	for _, p := range allow {
		if !worlds[p.W] {
			return c, nil, nil, reject("claim.allow: undeclared world")
		}
		has[p.W] = true
	}
	for w := range worlds {
		if !has[w] {
			return c, nil, nil, reject("claim.allow: world without allowed consequence")
		}
	}
	if err := ident("claim", c.ClaimID, "claim.claim_id"); err != nil {
		return c, nil, nil, err
	}
	if claimID(c, allow) != c.ClaimID {
		return c, nil, nil, reject("claim.claim_id: mismatch")
	}
	return c, allow, worlds, nil
}

func checkWitness(claimRaw, objRaw, artifactRaw, implementationRaw []byte) (Result, error) {
	c, allow, worlds, err := checkClaim(claimRaw)
	if err != nil {
		return nil, err
	}
	var w Witness
	if err := exact(objRaw, []string{"wire", "kind", "claim_id", "target_id", "pair", "grounding_proof", "evidence_roots", "witness_id"}, "witness", &w); err != nil {
		return nil, err
	}
	if w.Wire != "risu.k1.w0" || w.Kind != "regression_witness" || w.ClaimID != c.ClaimID {
		return nil, reject("witness: wire/kind/claim mismatch")
	}
	if err := ident("t", w.TargetID, "witness.target_id"); err != nil {
		return nil, err
	}
	p, err := parsePair(w.Pair[:], "witness.pair")
	if err != nil {
		return nil, err
	}
	if !worlds[p.W] {
		return nil, reject("witness: undeclared world")
	}
	for _, a := range allow {
		if a == p {
			return nil, reject("witness: observed consequence is allowed")
		}
	}
	if w.GroundingProof.Kind != proofKind {
		return nil, unsupported("unsupported grounding proof kind")
	}
	if err := ident("p", w.GroundingProof.Artifact, "witness.grounding_proof.artifact"); err != nil {
		return nil, err
	}
	seenRoot := map[string]bool{}
	for _, r := range w.EvidenceRoots {
		if err := ident("e", r, "witness.evidence_root"); err != nil {
			return nil, err
		}
		if seenRoot[r] {
			return nil, reject("witness.evidence_roots: duplicate")
		}
		seenRoot[r] = true
	}
	if err := ident("wit", w.WitnessID, "witness.witness_id"); err != nil {
		return nil, err
	}
	if witnessID(w) != w.WitnessID {
		return nil, reject("witness.witness_id: mismatch")
	}
	if digest("p:sha256:", artifactRaw) != w.GroundingProof.Artifact {
		return nil, reject("proof artifact: byte digest mismatch")
	}
	var a Artifact
	if err := exact(artifactRaw, []string{"proof_format", "profile", "claim_id", "target_id", "pair", "implementation_id", "world_input_b64", "effect_log_b64", "record_index", "timed_out", "exit_code", "stdout_sha256", "stderr_sha256"}, "observed-pair artifact", &a); err != nil {
		return nil, err
	}
	if a.ProofFormat != proofKind {
		return nil, unsupported("unsupported proof artifact format")
	}
	if a.Profile != profile {
		return nil, unsupported("unsupported observation profile")
	}
	if a.ClaimID != c.ClaimID || a.Pair != w.Pair {
		return nil, reject("observed-pair artifact: claim/pair mismatch")
	}
	if err := ident("t", a.TargetID, "observed-pair artifact.target_id"); err != nil {
		return nil, err
	}
	if err := ident("impl", a.ImplementationID, "observed-pair artifact.implementation_id"); err != nil {
		return nil, err
	}
	if digest("impl:sha256:", implementationRaw) != a.ImplementationID {
		return nil, reject("observed-pair artifact: implementation substitution")
	}
	if a.RecordIndex < 0 {
		return nil, reject("observed-pair artifact.record_index: invalid")
	}
	if !hex64RE.MatchString(a.StdoutSHA256) || !hex64RE.MatchString(a.StderrSHA256) {
		return nil, reject("observed-pair artifact: invalid stdout/stderr digest")
	}
	worldRaw, err := canonicalB64(a.WorldInputB64, "observed-pair artifact.world_input_b64")
	if err != nil {
		return nil, err
	}
	effectRaw, err := canonicalB64(a.EffectLogB64, "observed-pair artifact.effect_log_b64")
	if err != nil {
		return nil, err
	}
	if worldID(worldRaw) != p.W {
		return nil, reject("observed-pair artifact: world-input substitution")
	}
	cs, err := parseEffect(effectRaw)
	if err != nil {
		return nil, err
	}
	if a.RecordIndex >= len(cs) {
		return nil, reject("observed-pair artifact: record index out of range")
	}
	if cs[a.RecordIndex] != p.C {
		return nil, reject("observed-pair artifact: selected record does not ground witness consequence")
	}
	tid := targetID(a, worldRaw, effectRaw)
	if a.TargetID != tid || w.TargetID != tid {
		return nil, reject("observed-pair artifact: target commitment mismatch")
	}
	return Result{"checker": "risu-k1-checker-w4", "proof_status": "ACCEPTED", "semantic_claim": "REGRESSION", "assurance_scope": "LOCAL_OBSERVED_PAIR", "preservation_authority": false, "implementation_content_binding": true, "causal_execution_attestation": false, "claim_id": c.ClaimID, "target_id": tid, "witness_id": w.WitnessID, "witness_pair": []string{p.W, p.C}, "claim_world_count": len(worlds), "observed_world_count": 1}, nil
}

func main() {
	claimPath := flag.String("claim", "", "claim")
	objPath := flag.String("proof-object", "", "proof object")
	artifactPath := flag.String("artifact", "", "artifact")
	implPath := flag.String("implementation", "", "implementation")
	flag.Parse()
	if *claimPath == "" || *objPath == "" || *artifactPath == "" || *implPath == "" {
		fmt.Fprintln(os.Stderr, "required flags missing")
		os.Exit(64)
	}
	claimRaw, _ := os.ReadFile(*claimPath)
	objRaw, _ := os.ReadFile(*objPath)
	artifactRaw, _ := os.ReadFile(*artifactPath)
	implRaw, _ := os.ReadFile(*implPath)
	var kind struct {
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal(objRaw, &kind)
	var result Result
	var err error
	if kind.Kind == "preservation_certificate" {
		err = unsupported("k1.observed-pair/v1 has zero preservation authority")
	} else if kind.Kind != "regression_witness" {
		err = reject("proof object: unsupported kind")
	} else {
		result, err = checkWitness(claimRaw, objRaw, artifactRaw, implRaw)
	}
	rc := 0
	if err != nil {
		var ue unsupportedError
		if errors.As(err, &ue) {
			result = Result{"checker": "risu-k1-checker-w4", "proof_status": "UNSUPPORTED", "semantic_claim": "UNKNOWN", "preservation_authority": false, "reason": err.Error()}
			rc = 2
		} else {
			result = Result{"checker": "risu-k1-checker-w4", "proof_status": "REJECTED", "semantic_claim": "UNKNOWN", "preservation_authority": false, "reason": err.Error()}
			rc = 1
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
	os.Exit(rc)
}
