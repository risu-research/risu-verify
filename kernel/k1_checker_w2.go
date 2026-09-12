package main

// RISU K1 checker W2 is an implementation-independent corroborating checker
// for the frozen RC1 W0 + k1.finite-model/v1 fragment.
//
// Independence rule: this file is implemented from the W0 protocol/schema and
// finite-model/v1 behavior. It imports no RISU checker code, executes no Python,
// and uses only the Go standard library.

import (
	"bytes"
	"crypto/sha256"
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

const proofKind = "k1.finite-model/v1"

type rejectError struct{ msg string }
func (e rejectError) Error() string { return e.msg }

type unsupportedError struct{ msg string }
func (e unsupportedError) Error() string { return e.msg }

func reject(msg string) error { return rejectError{msg: msg} }
func unsupported(msg string) error { return unsupportedError{msg: msg} }

var idRE = map[string]*regexp.Regexp{
	"w":     regexp.MustCompile(`^w:sha256:[0-9a-f]{64}$`),
	"c":     regexp.MustCompile(`^c:sha256:[0-9a-f]{64}$`),
	"t":     regexp.MustCompile(`^t:sha256:[0-9a-f]{64}$`),
	"p":     regexp.MustCompile(`^p:sha256:[0-9a-f]{64}$`),
	"e":     regexp.MustCompile(`^e:sha256:[0-9a-f]{64}$`),
	"claim": regexp.MustCompile(`^claim:sha256:[0-9a-f]{64}$`),
	"cert":  regexp.MustCompile(`^cert:sha256:[0-9a-f]{64}$`),
	"wit":   regexp.MustCompile(`^wit:sha256:[0-9a-f]{64}$`),
}

var proofKindRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)

type Pair struct {
	World       string
	Consequence string
}

type ProofRef struct {
	Kind     string `json:"kind"`
	Artifact string `json:"artifact"`
}

type GroundingEntry struct {
	Pair  [2]string `json:"pair"`
	Proof ProofRef  `json:"proof"`
}

type Claim struct {
	Wire      string     `json:"wire"`
	Kind      string     `json:"kind"`
	Semantics string     `json:"semantics"`
	Worlds    []string   `json:"worlds"`
	Allow     [][]string `json:"allow"`
	ClaimID   string     `json:"claim_id"`
}

type Certificate struct {
	Wire             string           `json:"wire"`
	Kind             string           `json:"kind"`
	ClaimID          string           `json:"claim_id"`
	TargetID         string           `json:"target_id"`
	Realize          [][]string       `json:"realize"`
	ClosureProof     ProofRef         `json:"closure_proof"`
	GroundingProofs  []GroundingEntry `json:"grounding_proofs"`
	EvidenceRoots    []string         `json:"evidence_roots"`
	CertificateID    string           `json:"certificate_id"`
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

type FiniteArtifact struct {
	ProofFormat string     `json:"proof_format"`
	ClaimID     string     `json:"claim_id"`
	TargetID    string     `json:"target_id"`
	Worlds      []string   `json:"worlds"`
	Possible    [][]string `json:"possible"`
}

type Result map[string]any

func readFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil { return nil, reject("cannot read " + path + ": " + err.Error()) }
	return b, nil
}

func exactObject(raw []byte, expected []string, where string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, reject(where + ": malformed object")
	}
	if len(m) != len(expected) { return nil, reject(where + ": malformed object") }
	for _, k := range expected {
		if _, ok := m[k]; !ok { return nil, reject(where + ": malformed object") }
	}
	return m, nil
}

func decodeExact(raw []byte, expected []string, where string, out any) (map[string]json.RawMessage, error) {
	m, err := exactObject(raw, expected, where)
	if err != nil { return nil, err }
	if err := json.Unmarshal(raw, out); err != nil { return nil, reject(where + ": malformed object") }
	return m, nil
}

func validateProofRefRaw(raw []byte, where string) (ProofRef, error) {
	var p ProofRef
	if _, err := decodeExact(raw, []string{"kind", "artifact"}, where, &p); err != nil { return p, err }
	if !proofKindRE.MatchString(p.Kind) { return p, reject(where + ".kind: noncanonical proof kind") }
	if err := ident("p", p.Artifact, where+".artifact"); err != nil { return p, err }
	return p, nil
}

func validateCertificateNested(top map[string]json.RawMessage) error {
	if _, err := validateProofRefRaw(top["closure_proof"], "certificate.closure_proof"); err != nil { return err }
	var rows []json.RawMessage
	if err := json.Unmarshal(top["grounding_proofs"], &rows); err != nil { return reject("certificate.grounding_proofs: malformed") }
	for i, raw := range rows {
		var m map[string]json.RawMessage
		var entry GroundingEntry
		var err error
		m, err = decodeExact(raw, []string{"pair", "proof"}, fmt.Sprintf("certificate.grounding_proofs[%d]", i), &entry)
		if err != nil { return err }
		if _, err := parseOnePair(entry.Pair[:], fmt.Sprintf("certificate.grounding_proofs[%d].pair", i)); err != nil { return err }
		if _, err := validateProofRefRaw(m["proof"], fmt.Sprintf("certificate.grounding_proofs[%d].proof", i)); err != nil { return err }
	}
	return nil
}

func validateWitnessNested(top map[string]json.RawMessage) error {
	_, err := validateProofRefRaw(top["grounding_proof"], "witness.grounding_proof")
	return err
}

func ident(kind, value, where string) error {
	r, ok := idRE[kind]
	if !ok || !r.MatchString(value) { return reject(where + ": noncanonical identifier") }
	return nil
}

func net(s string) []byte {
	return []byte(strconv.Itoa(len([]byte(s))) + ":" + s + ",")
}

func vals(tag string, xs []string) []byte {
	var b bytes.Buffer
	b.WriteString(tag)
	b.Write(net(strconv.Itoa(len(xs))))
	for _, x := range xs { b.WriteByte('V'); b.Write(net(x)) }
	return b.Bytes()
}

func pairLess(a, b Pair) bool {
	if a.World != b.World { return a.World < b.World }
	return a.Consequence < b.Consequence
}

func sortedPairs(xs []Pair) []Pair {
	out := append([]Pair(nil), xs...)
	sort.Slice(out, func(i, j int) bool { return pairLess(out[i], out[j]) })
	return out
}

func pairsTranscript(tag string, xs []Pair) []byte {
	var b bytes.Buffer
	b.WriteString(tag)
	b.Write(net(strconv.Itoa(len(xs))))
	for _, p := range xs { b.WriteByte('P'); b.Write(net(p.World)); b.Write(net(p.Consequence)) }
	return b.Bytes()
}

func digest(prefix string, pre []byte) string {
	h := sha256.Sum256(pre)
	return prefix + hex.EncodeToString(h[:])
}

func parseOnePair(row []string, where string) (Pair, error) {
	var p Pair
	if len(row) != 2 { return p, reject(where + ": expected pair") }
	if err := ident("w", row[0], where+".world"); err != nil { return p, err }
	if err := ident("c", row[1], where+".consequence"); err != nil { return p, err }
	return Pair{World: row[0], Consequence: row[1]}, nil
}

func parseRelation(rows [][]string, where string) ([]Pair, error) {
	out := make([]Pair, 0, len(rows))
	seen := map[Pair]bool{}
	for i, row := range rows {
		p, err := parseOnePair(row, fmt.Sprintf("%s[%d]", where, i))
		if err != nil { return nil, err }
		if seen[p] { return nil, reject(where + ": duplicate pair") }
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

func claimID(c Claim, allow []Pair) string {
	ws := append([]string(nil), c.Worlds...)
	sort.Strings(ws)
	as := sortedPairs(allow)
	var b bytes.Buffer
	b.Write([]byte("RISU-K1-CLAIM-W0\x00"))
	b.WriteByte('S'); b.Write(net(c.Semantics)); b.Write(vals("W", ws)); b.Write(pairsTranscript("A", as))
	return digest("claim:sha256:", b.Bytes())
}

func targetID(worlds []string, possible []Pair) string {
	ws := append([]string(nil), worlds...)
	sort.Strings(ws)
	ps := sortedPairs(possible)
	var b bytes.Buffer
	b.Write([]byte("RISU-K1-TARGET-FINITE-V1\x00"))
	b.Write(vals("W", ws)); b.Write(pairsTranscript("R", ps))
	return digest("t:sha256:", b.Bytes())
}

type GroundBind struct { W, C, Kind, Artifact string }
func sortedGround(xs []GroundBind) []GroundBind {
	out := append([]GroundBind(nil), xs...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.W != b.W { return a.W < b.W }
		if a.C != b.C { return a.C < b.C }
		if a.Kind != b.Kind { return a.Kind < b.Kind }
		return a.Artifact < b.Artifact
	})
	return out
}

func certificateID(c Certificate, realize []Pair) string {
	rs := sortedPairs(realize)
	gs := make([]GroundBind, 0, len(c.GroundingProofs))
	for _, g := range c.GroundingProofs {
		gs = append(gs, GroundBind{g.Pair[0], g.Pair[1], g.Proof.Kind, g.Proof.Artifact})
	}
	gs = sortedGround(gs)
	roots := append([]string(nil), c.EvidenceRoots...); sort.Strings(roots)
	var b bytes.Buffer
	b.Write([]byte("RISU-K1-CERT-W0\x00"))
	b.WriteByte('C'); b.Write(net(c.ClaimID)); b.WriteByte('T'); b.Write(net(c.TargetID))
	b.Write(pairsTranscript("R", rs)); b.WriteByte('Q'); b.Write(net(c.ClosureProof.Kind)); b.Write(net(c.ClosureProof.Artifact))
	b.WriteByte('G'); b.Write(net(strconv.Itoa(len(gs))))
	for _, g := range gs { b.WriteByte('g'); b.Write(net(g.W)); b.Write(net(g.C)); b.Write(net(g.Kind)); b.Write(net(g.Artifact)) }
	b.Write(vals("E", roots))
	return digest("cert:sha256:", b.Bytes())
}

func witnessID(w Witness) string {
	roots := append([]string(nil), w.EvidenceRoots...); sort.Strings(roots)
	var b bytes.Buffer
	b.Write([]byte("RISU-K1-WIT-W0\x00"))
	b.WriteByte('C'); b.Write(net(w.ClaimID)); b.WriteByte('T'); b.Write(net(w.TargetID))
	b.WriteByte('P'); b.Write(net(w.Pair[0])); b.Write(net(w.Pair[1]))
	b.WriteByte('G'); b.Write(net(w.GroundingProof.Kind)); b.Write(net(w.GroundingProof.Artifact)); b.Write(vals("E", roots))
	return digest("wit:sha256:", b.Bytes())
}

func checkClaimRaw(raw []byte) (Claim, []Pair, error) {
	var c Claim
	_, err := decodeExact(raw, []string{"wire", "kind", "semantics", "worlds", "allow", "claim_id"}, "claim", &c)
	if err != nil { return c, nil, err }
	if c.Wire != "risu.k1.w0" || c.Kind != "claim" || c.Semantics != "safety-subset-v1" { return c, nil, reject("claim: unsupported wire/semantics") }
	if len(c.Worlds) == 0 { return c, nil, reject("claim.worlds: empty") }
	worldSet := map[string]bool{}
	for _, w := range c.Worlds {
		if err := ident("w", w, "claim.world"); err != nil { return c, nil, err }
		if worldSet[w] { return c, nil, reject("claim.worlds: duplicate") }
		worldSet[w] = true
	}
	allow, err := parseRelation(c.Allow, "claim.allow")
	if err != nil { return c, nil, err }
	if len(allow) == 0 { return c, nil, reject("claim.allow: empty") }
	hasAllow := map[string]bool{}
	for _, p := range allow {
		if !worldSet[p.World] { return c, nil, reject("claim.allow: undeclared world") }
		hasAllow[p.World] = true
	}
	for w := range worldSet { if !hasAllow[w] { return c, nil, reject("claim.allow: world without allowed consequence") } }
	if err := ident("claim", c.ClaimID, "claim.claim_id"); err != nil { return c, nil, err }
	if c.ClaimID != claimID(c, allow) { return c, nil, reject("claim.claim_id: mismatch") }
	return c, allow, nil
}

func hashArtifact(raw []byte) string { return digest("p:sha256:", raw) }

func checkArtifact(raw []byte, expectedArtifact string, claim Claim) (FiniteArtifact, []Pair, error) {
	var a FiniteArtifact
	if hashArtifact(raw) != expectedArtifact { return a, nil, reject("proof artifact: byte digest mismatch") }
	if _, err := decodeExact(raw, []string{"proof_format", "claim_id", "target_id", "worlds", "possible"}, "finite-model proof", &a); err != nil { return a, nil, reject("proof artifact: invalid or malformed JSON") }
	if a.ProofFormat != proofKind { return a, nil, unsupported("unsupported proof artifact format") }
	if a.ClaimID != claim.ClaimID { return a, nil, reject("finite-model proof: claim mismatch") }
	worldSet := map[string]bool{}
	for _, w := range claim.Worlds { worldSet[w] = true }
	if len(a.Worlds) != len(claim.Worlds) { return a, nil, reject("finite-model proof: world domain mismatch") }
	seenWorld := map[string]bool{}
	for _, w := range a.Worlds {
		if err := ident("w", w, "finite-model proof.world"); err != nil { return a, nil, err }
		if !worldSet[w] || seenWorld[w] { return a, nil, reject("finite-model proof: world domain mismatch") }
		seenWorld[w] = true
	}
	possible, err := parseRelation(a.Possible, "finite-model proof.possible")
	if err != nil { return a, nil, err }
	if len(possible) == 0 { return a, nil, reject("finite-model proof: empty target relation") }
	total := map[string]bool{}
	for _, p := range possible {
		if !worldSet[p.World] { return a, nil, reject("finite-model proof: undeclared world") }
		total[p.World] = true
	}
	for w := range worldSet { if !total[w] { return a, nil, reject("finite-model proof: non-total consequential cut") } }
	if err := ident("t", a.TargetID, "finite-model proof.target_id"); err != nil { return a, nil, err }
	if a.TargetID != targetID(claim.Worlds, possible) { return a, nil, reject("finite-model proof: target commitment mismatch") }
	return a, possible, nil
}

func uniqueEvidence(xs []string, where string) error {
	seen := map[string]bool{}
	for _, x := range xs {
		if err := ident("e", x, where); err != nil { return err }
		if seen[x] { return reject(strings.TrimSuffix(where, ".evidence_root") + ".evidence_roots: malformed") }
		seen[x] = true
	}
	return nil
}

func pairSet(xs []Pair) map[Pair]bool { m := map[Pair]bool{}; for _, p := range xs { m[p] = true }; return m }

func checkCertificate(raw []byte, claimRaw []byte, artifactRaw []byte) (Result, error) {
	var cert Certificate
	top, err := decodeExact(raw, []string{"wire", "kind", "claim_id", "target_id", "realize", "closure_proof", "grounding_proofs", "evidence_roots", "certificate_id"}, "certificate", &cert)
	if err != nil { return nil, err }
	if err := validateCertificateNested(top); err != nil { return nil, err }
	claim, allow, err := checkClaimRaw(claimRaw); if err != nil { return nil, err }
	if cert.Wire != "risu.k1.w0" || cert.Kind != "preservation_certificate" || cert.ClaimID != claim.ClaimID { return nil, reject("certificate: wire/kind/claim mismatch") }
	if err := ident("t", cert.TargetID, "certificate.target_id"); err != nil { return nil, err }
	realize, err := parseRelation(cert.Realize, "certificate.realize"); if err != nil { return nil, err }
	if len(realize) == 0 { return nil, reject("certificate.realize: empty or undeclared world") }
	worldSet := map[string]bool{}; for _, w := range claim.Worlds { worldSet[w] = true }
	for _, p := range realize { if !worldSet[p.World] { return nil, reject("certificate.realize: empty or undeclared world") } }
	if cert.ClosureProof.Kind != proofKind { return nil, unsupported("unsupported closure proof kind") }
	if err := uniqueEvidence(cert.EvidenceRoots, "certificate.evidence_root"); err != nil { return nil, err }
	if err := ident("cert", cert.CertificateID, "certificate.certificate_id"); err != nil { return nil, err }
	if cert.CertificateID != certificateID(cert, realize) { return nil, reject("certificate.certificate_id: mismatch") }

	grounded := map[Pair]ProofRef{}
	for _, g := range cert.GroundingProofs {
		p, err := parseOnePair(g.Pair[:], "certificate.grounding_entry.pair"); if err != nil { return nil, err }
		if _, ok := grounded[p]; ok { return nil, reject("certificate.grounding_proofs: duplicate pair") }
		grounded[p] = g.Proof
	}

	a, possible, err := checkArtifact(artifactRaw, cert.ClosureProof.Artifact, claim); if err != nil { return nil, err }
	if cert.TargetID != a.TargetID { return nil, reject("certificate: target/proof mismatch") }
	if !samePairSet(realize, possible) { return nil, reject("certificate: closure proof does not establish submitted REALIZE as exhaustive") }
	for _, p := range realize {
		ref, ok := grounded[p]
		if !ok { return nil, reject("certificate: REALIZE pair lacks grounding proof") }
		if ref.Kind != proofKind { return nil, unsupported("unsupported grounding proof kind") }
		if ref.Artifact != cert.ClosureProof.Artifact { return nil, reject("certificate: grounding artifact differs from finite closure model") }
	}
	if len(grounded) != len(realize) { return nil, reject("certificate: grounding set is not exactly REALIZE") }
	allowSet := pairSet(allow)
	for _, p := range realize { if !allowSet[p] { return nil, reject("certificate: forbidden realized consequence present") } }
	return Result{
		"checker": "risu-k1-checker-w2-go", "proof_status": "ACCEPTED", "semantic_claim": "PRESERVATION",
		"assurance_scope": "DECLARED_FINITE_TARGET_MODEL", "implementation_binding": false,
		"claim_id": claim.ClaimID, "target_id": cert.TargetID, "certificate_id": cert.CertificateID,
		"world_count": len(claim.Worlds), "realize_pair_count": len(realize),
	}, nil
}

func checkWitness(raw []byte, claimRaw []byte, artifactRaw []byte) (Result, error) {
	var wit Witness
	top, err := decodeExact(raw, []string{"wire", "kind", "claim_id", "target_id", "pair", "grounding_proof", "evidence_roots", "witness_id"}, "witness", &wit)
	if err != nil { return nil, err }
	if err := validateWitnessNested(top); err != nil { return nil, err }
	claim, allow, err := checkClaimRaw(claimRaw); if err != nil { return nil, err }
	if wit.Wire != "risu.k1.w0" || wit.Kind != "regression_witness" || wit.ClaimID != claim.ClaimID { return nil, reject("witness: wire/kind/claim mismatch") }
	if err := ident("t", wit.TargetID, "witness.target_id"); err != nil { return nil, err }
	p, err := parseOnePair(wit.Pair[:], "witness.pair"); if err != nil { return nil, err }
	worldSet := map[string]bool{}; for _, w := range claim.Worlds { worldSet[w] = true }
	if !worldSet[p.World] { return nil, reject("witness: undeclared world") }
	if wit.GroundingProof.Kind != proofKind { return nil, unsupported("unsupported grounding proof kind") }
	if err := uniqueEvidence(wit.EvidenceRoots, "witness.evidence_root"); err != nil { return nil, err }
	if err := ident("wit", wit.WitnessID, "witness.witness_id"); err != nil { return nil, err }
	if wit.WitnessID != witnessID(wit) { return nil, reject("witness.witness_id: mismatch") }
	a, possible, err := checkArtifact(artifactRaw, wit.GroundingProof.Artifact, claim); if err != nil { return nil, err }
	if wit.TargetID != a.TargetID { return nil, reject("witness: target/proof mismatch") }
	possibleSet := pairSet(possible); if !possibleSet[p] { return nil, reject("witness: pair not grounded by finite target model") }
	allowSet := pairSet(allow); if allowSet[p] { return nil, reject("witness: realized consequence is allowed") }
	return Result{
		"checker": "risu-k1-checker-w2-go", "proof_status": "ACCEPTED", "semantic_claim": "REGRESSION",
		"assurance_scope": "DECLARED_FINITE_TARGET_MODEL", "implementation_binding": false,
		"claim_id": claim.ClaimID, "target_id": wit.TargetID, "witness_id": wit.WitnessID,
		"witness_pair": []string{p.World, p.Consequence},
	}, nil
}

func samePairSet(a, b []Pair) bool {
	if len(a) != len(b) { return false }
	ma := pairSet(a); for _, p := range b { if !ma[p] { return false } }
	return true
}

func proofObjectKind(raw []byte) (string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil { return "", reject("proof object: invalid JSON") }
	var k string
	r, ok := m["kind"]; if !ok || json.Unmarshal(r, &k) != nil { return "", reject("proof object: unsupported kind") }
	return k, nil
}

func emit(v any) { enc := json.NewEncoder(os.Stdout); enc.SetIndent("", "  "); _ = enc.Encode(v) }

func main() {
	claimPath := flag.String("claim", "", "W0 claim JSON")
	proofPath := flag.String("proof-object", "", "W0 preservation certificate or regression witness JSON")
	artifactPath := flag.String("artifact", "", "exact finite-model proof artifact bytes")
	flag.Parse()
	if *claimPath == "" || *proofPath == "" || *artifactPath == "" {
		emit(Result{"checker":"risu-k1-checker-w2-go", "proof_status":"REJECTED", "semantic_claim":"NONE", "reason":"missing required arguments"}); os.Exit(1)
	}
	claimRaw, err := readFile(*claimPath); if err != nil { emitError(err); return }
	proofRaw, err := readFile(*proofPath); if err != nil { emitError(err); return }
	artifactRaw, err := readFile(*artifactPath); if err != nil { emitError(err); return }
	kind, err := proofObjectKind(proofRaw); if err != nil { emitError(err); return }
	var result Result
	switch kind {
	case "preservation_certificate": result, err = checkCertificate(proofRaw, claimRaw, artifactRaw)
	case "regression_witness": result, err = checkWitness(proofRaw, claimRaw, artifactRaw)
	default: err = reject("proof object: unsupported kind")
	}
	if err != nil { emitError(err); return }
	emit(result)
}

func emitError(err error) {
	var u unsupportedError
	if errors.As(err, &u) {
		emit(Result{"checker":"risu-k1-checker-w2-go", "proof_status":"UNSUPPORTED", "semantic_claim":"UNKNOWN", "reason":u.msg})
		os.Exit(2)
	}
	var r rejectError
	if errors.As(err, &r) {
		emit(Result{"checker":"risu-k1-checker-w2-go", "proof_status":"REJECTED", "semantic_claim":"NONE", "reason":r.msg})
		os.Exit(1)
	}
	emit(Result{"checker":"risu-k1-checker-w2-go", "proof_status":"REJECTED", "semantic_claim":"NONE", "reason":err.Error()})
	os.Exit(1)
}
