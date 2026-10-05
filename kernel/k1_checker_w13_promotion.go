package main

// P0 candidate production-promotion checker W13 (Go).
// Non-production: validates the composition around the Q0-qualified W10/W11
// pair and the existing W0 certificate transcript. It creates no authority.

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
)

const (
	proofFormat = "risu.k1.mediated-refinement-proof/v1"
	proofKind   = "k1.mediated-refinement/v1"
	sourceSem   = "risu.k1.c3.mfst/v1"
	downstream  = "k1.capsule-closure/v1"
	scope       = "EXACT_MFST_SOURCE_TO_EXACT_QUALIFIED_C2_LOWERING"
	q0Candidate = "A1"
	q0Commit    = "a857fe1f72b7341d549354e9ccc330dca22e9c0d"
	q0Blob      = "592afac89231040280e9e29ba26292c18f90b9e6"
	w10Blob     = "5eea6fa26bdb488d60743a4bf3470cd5bd28eab3"
	w11Blob     = "1434a9255d42ad9e9b8d57f9e1c1fa1d47c6a8a0"
)

var sourcePins = map[string]string{
	"w10_source":      w10Blob,
	"w11_source":      w11Blob,
	"w7_model_source": "3c351fd445b704d693e05ba01efe9cffa6a2801b",
	"w7_exec_source":  "8b1529dfbd8367e20776f0ab8ec3f5fa6559ca2a",
	"w7_source":       "c011532efbe9b6dcd6ae440705ce7b38c5dde93b",
	"w8_json_source":  "4e770c8ef7882b23705bb7068bd877c2cd9c3543",
	"w8_model_source": "b53897a82255886d59b9dc05d7fbe8166aca1d35",
	"w8_exec_source":  "64254a8537d3777848b1d3f8176260c5a1c312e7",
	"w8_source":       "f3e1e0c42e8106615b0aeeb2a85ceae3046e74a2",
	"w5_source":       "cf08aff1ce9f9506df37d597c2fc348bfefd6331",
	"w6_source":       "33464fe4132d6490b1a68cc71ef803d584e597f9",
}

var promoKeys = map[string]bool{
	"proof_format": true, "proof_kind": true, "claim_id": true, "source_semantics": true,
	"downstream_proof_kind": true, "authority_scope": true, "profile_sha256": true,
	"c3_certificate_sha256": true, "c3_certificate_id": true, "c2_program_sha256": true,
	"c2_artifact_id": true, "c2_target_id": true, "q0_candidate_id": true,
	"q0_qualification_anchor_commit": true, "q0_qualification_anchor_blob": true,
	"w10_blob": true, "w11_blob": true,
}
var outerKeys = map[string]bool{
	"wire": true, "kind": true, "claim_id": true, "target_id": true, "realize": true,
	"closure_proof": true, "grounding_proofs": true, "evidence_roots": true, "certificate_id": true,
}

var patterns = map[string]*regexp.Regexp{
	"claim":  regexp.MustCompile("^claim:sha256:[0-9a-f]{64}$"),
	"c3cert": regexp.MustCompile("^c3cert:sha256:[0-9a-f]{64}$"),
	"sha":    regexp.MustCompile("^[0-9a-f]{64}$"),
	"p":      regexp.MustCompile("^p:sha256:[0-9a-f]{64}$"),
	"t":      regexp.MustCompile("^t:sha256:[0-9a-f]{64}$"),
	"w":      regexp.MustCompile("^w:sha256:[0-9a-f]{64}$"),
	"c":      regexp.MustCompile("^c:sha256:[0-9a-f]{64}$"),
	"e":      regexp.MustCompile("^e:sha256:[0-9a-f]{64}$"),
	"cert":   regexp.MustCompile("^cert:sha256:[0-9a-f]{64}$"),
}

type Pair struct{ W, C string }

func walkValue(d *json.Decoder) error {
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			kt, err := d.Token()
			if err != nil {
				return err
			}
			k, ok := kt.(string)
			if !ok {
				return errors.New("object key is not string")
			}
			if seen[k] {
				return fmt.Errorf("duplicate JSON key:%s", k)
			}
			seen[k] = true
			if err := walkValue(d); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("object terminator")
		}
	case '[':
		for d.More() {
			if err := walkValue(d); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("array terminator")
		}
	default:
		return errors.New("unexpected delimiter")
	}
	return nil
}

func strictRaw(raw []byte, where string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := walkValue(d); err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	if _, err := d.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s: trailing JSON", where)
		}
		return nil, fmt.Errorf("%s: trailing data", where)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("%s: invalid object", where)
	}
	return m, nil
}

func exactKeys(m map[string]json.RawMessage, want map[string]bool) bool {
	if len(m) != len(want) {
		return false
	}
	for k := range m {
		if !want[k] {
			return false
		}
	}
	return true
}
func strField(m map[string]json.RawMessage, k string) (string, error) {
	var s string
	if err := json.Unmarshal(m[k], &s); err != nil {
		return "", fmt.Errorf("field %s not string", k)
	}
	return s, nil
}
func net(s string) []byte {
	b := []byte(s)
	return []byte(strconv.Itoa(len(b)) + ":" + s + ",")
}
func gitBlob(raw []byte) string {
	h := sha1.New()
	h.Write([]byte("blob " + strconv.Itoa(len(raw)) + "\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func sha256hex(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func read(path string) ([]byte, error) { return os.ReadFile(path) }

func relation(raw json.RawMessage, where string) ([]Pair, error) {
	var rows [][]string
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("%s: not pair array", where)
	}
	seen := map[string]bool{}
	out := make([]Pair, 0, len(rows))
	for _, r := range rows {
		if len(r) != 2 || !patterns["w"].MatchString(r[0]) || !patterns["c"].MatchString(r[1]) {
			return nil, fmt.Errorf("%s: bad pair", where)
		}
		key := r[0] + "\x00" + r[1]
		if seen[key] {
			return nil, fmt.Errorf("%s: duplicate pair", where)
		}
		seen[key] = true
		out = append(out, Pair{r[0], r[1]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].W != out[j].W {
			return out[i].W < out[j].W
		}
		return out[i].C < out[j].C
	})
	return out, nil
}
func pairsEqual(a, b []Pair) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func evidenceRoot(claim, artifact, c3id, target string) string {
	pre := []byte("RISU-K1-MEDIATED-REFINEMENT-PROOF-V1\x00")
	for _, tv := range []struct {
		t byte
		v string
	}{
		{'C', claim}, {'A', artifact}, {'R', c3id}, {'T', target},
		{'Q', q0Commit}, {'X', w10Blob}, {'Y', w11Blob},
	} {
		pre = append(pre, tv.t)
		pre = append(pre, net(tv.v)...)
	}
	h := sha256.Sum256(pre)
	return "e:sha256:" + hex.EncodeToString(h[:])
}

type proofRef struct {
	Kind     string `json:"kind"`
	Artifact string `json:"artifact"`
}
type grounding struct {
	Pair  []string `json:"pair"`
	Proof proofRef `json:"proof"`
}

func outerCertID(m map[string]json.RawMessage) (string, error) {
	claim, err := strField(m, "claim_id")
	if err != nil {
		return "", err
	}
	target, err := strField(m, "target_id")
	if err != nil {
		return "", err
	}
	real, err := relation(m["realize"], "outer.realize")
	if err != nil {
		return "", err
	}
	var cp proofRef
	if err := json.Unmarshal(m["closure_proof"], &cp); err != nil {
		return "", errors.New("outer closure proof")
	}
	var cpm map[string]json.RawMessage
	if err := json.Unmarshal(m["closure_proof"], &cpm); err != nil || len(cpm) != 2 {
		return "", errors.New("outer closure proof shape")
	}
	if _, ok := cpm["kind"]; !ok {
		return "", errors.New("outer closure proof shape")
	}
	if _, ok := cpm["artifact"]; !ok {
		return "", errors.New("outer closure proof shape")
	}
	var gs []grounding
	if err := json.Unmarshal(m["grounding_proofs"], &gs); err != nil {
		return "", errors.New("outer grounding")
	}
	type grow struct{ W, C, K, A string }
	gr := make([]grow, 0, len(gs))
	for _, g := range gs {
		if len(g.Pair) != 2 || !patterns["w"].MatchString(g.Pair[0]) || !patterns["c"].MatchString(g.Pair[1]) {
			return "", errors.New("outer grounding pair")
		}
		gr = append(gr, grow{g.Pair[0], g.Pair[1], g.Proof.Kind, g.Proof.Artifact})
	}
	sort.Slice(gr, func(i, j int) bool {
		a, b := gr[i], gr[j]
		if a.W != b.W {
			return a.W < b.W
		}
		if a.C != b.C {
			return a.C < b.C
		}
		if a.K != b.K {
			return a.K < b.K
		}
		return a.A < b.A
	})
	var roots []string
	if err := json.Unmarshal(m["evidence_roots"], &roots); err != nil {
		return "", errors.New("outer roots")
	}
	sort.Strings(roots)
	pre := []byte("RISU-K1-CERT-W0\x00")
	pre = append(pre, 'C')
	pre = append(pre, net(claim)...)
	pre = append(pre, 'T')
	pre = append(pre, net(target)...)
	pre = append(pre, 'R')
	pre = append(pre, net(strconv.Itoa(len(real)))...)
	for _, p := range real {
		pre = append(pre, 'P')
		pre = append(pre, net(p.W)...)
		pre = append(pre, net(p.C)...)
	}
	pre = append(pre, 'Q')
	pre = append(pre, net(cp.Kind)...)
	pre = append(pre, net(cp.Artifact)...)
	pre = append(pre, 'G')
	pre = append(pre, net(strconv.Itoa(len(gr)))...)
	for _, g := range gr {
		pre = append(pre, 'g')
		pre = append(pre, net(g.W)...)
		pre = append(pre, net(g.C)...)
		pre = append(pre, net(g.K)...)
		pre = append(pre, net(g.A)...)
	}
	pre = append(pre, 'E')
	pre = append(pre, net(strconv.Itoa(len(roots)))...)
	for _, r := range roots {
		pre = append(pre, 'V')
		pre = append(pre, net(r)...)
	}
	h := sha256.Sum256(pre)
	return "cert:sha256:" + hex.EncodeToString(h[:]), nil
}

func runJSON(name string, args ...string) (map[string]interface{}, error) {
	c := exec.Command(name, args...)
	var out bytes.Buffer
	c.Stdout = &out
	var er bytes.Buffer
	c.Stderr = &er
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("inner checker non-success: %v %s", err, er.String())
	}
	var m map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		return nil, errors.New("inner checker malformed output")
	}
	return m, nil
}
func sval(m map[string]interface{}, k string) string { v, _ := m[k].(string); return v }
func nval(m map[string]interface{}, k string) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return -1
}

type argsT struct {
	claim, profile, c3cert, program, c2artifact, promo, outer string
	w10, w11, w7, w8, w5, w6                                  string
	sources                                                   map[string]string
}

func reject(reason string) map[string]interface{} {
	return map[string]interface{}{"checker": "risu-k1-c3-promotion-w13", "proof_status": "REJECTED", "semantic_claim": "NONE", "authority_created": false, "reason": reason}
}

func check(a argsT) (map[string]interface{}, error) {
	for k, expected := range sourcePins {
		raw, err := read(a.sources[k])
		if err != nil {
			return nil, fmt.Errorf("source pin read:%s", k)
		}
		if gitBlob(raw) != expected {
			return nil, fmt.Errorf("source pin mismatch:%s", k)
		}
	}
	claimRaw, err := read(a.claim)
	if err != nil {
		return nil, err
	}
	claim, err := strictRaw(claimRaw, "claim")
	if err != nil {
		return nil, err
	}
	claimID, err := strField(claim, "claim_id")
	if err != nil || !patterns["claim"].MatchString(claimID) {
		return nil, errors.New("claim id")
	}

	promoRaw, err := read(a.promo)
	if err != nil {
		return nil, err
	}
	promo, err := strictRaw(promoRaw, "promotion")
	if err != nil {
		return nil, err
	}
	if !exactKeys(promo, promoKeys) {
		return nil, errors.New("promotion exact-key violation")
	}
	lits := map[string]string{
		"proof_format": proofFormat, "proof_kind": proofKind, "source_semantics": sourceSem,
		"downstream_proof_kind": downstream, "authority_scope": scope, "q0_candidate_id": q0Candidate,
		"q0_qualification_anchor_commit": q0Commit, "q0_qualification_anchor_blob": q0Blob,
		"w10_blob": w10Blob, "w11_blob": w11Blob,
	}
	for k, v := range lits {
		s, e := strField(promo, k)
		if e != nil || s != v {
			return nil, fmt.Errorf("promotion policy mismatch:%s", k)
		}
	}
	pClaim, _ := strField(promo, "claim_id")
	if pClaim != claimID {
		return nil, errors.New("promotion claim mismatch")
	}
	checkPatterns := map[string]string{"claim_id": "claim", "c3_certificate_id": "c3cert", "profile_sha256": "sha", "c3_certificate_sha256": "sha", "c2_program_sha256": "sha", "c2_artifact_id": "p", "c2_target_id": "t"}
	for k, p := range checkPatterns {
		s, e := strField(promo, k)
		if e != nil || !patterns[p].MatchString(s) {
			return nil, fmt.Errorf("promotion malformed:%s", k)
		}
	}

	profileRaw, _ := read(a.profile)
	certRaw, _ := read(a.c3cert)
	progRaw, _ := read(a.program)
	artRaw, _ := read(a.c2artifact)
	pProfile, _ := strField(promo, "profile_sha256")
	if sha256hex(profileRaw) != pProfile {
		return nil, errors.New("profile exact-byte mismatch")
	}
	pCertHash, _ := strField(promo, "c3_certificate_sha256")
	if sha256hex(certRaw) != pCertHash {
		return nil, errors.New("C3 certificate exact-byte mismatch")
	}
	pProg, _ := strField(promo, "c2_program_sha256")
	if sha256hex(progRaw) != pProg {
		return nil, errors.New("C2 program digest mismatch")
	}
	pAid, _ := strField(promo, "c2_artifact_id")
	if "p:sha256:"+sha256hex(artRaw) != pAid {
		return nil, errors.New("C2 artifact digest mismatch")
	}

	inner, err := strictRaw(certRaw, "C3 certificate")
	if err != nil {
		return nil, err
	}
	iClaim, _ := strField(inner, "claim_id")
	if iClaim != claimID {
		return nil, errors.New("inner claim mismatch")
	}
	iCID, _ := strField(inner, "certificate_id")
	pCID, _ := strField(promo, "c3_certificate_id")
	if iCID != pCID {
		return nil, errors.New("promotion C3 certificate id mismatch")
	}
	iTarget, _ := strField(inner, "c2_target_id")
	pTarget, _ := strField(promo, "c2_target_id")
	if iTarget != pTarget {
		return nil, errors.New("promotion target mismatch")
	}
	innerReal, err := relation(inner["projected_realize"], "inner projected_realize")
	if err != nil {
		return nil, err
	}

	common := []string{"--claim", a.claim, "--profile", a.profile, "--certificate", a.c3cert, "--program", a.program, "--artifact", a.c2artifact, "--w7", a.w7, "--w8", a.w8, "--w5", a.w5, "--w6", a.w6}
	r10, err := runJSON("python3", append([]string{a.w10}, common...)...)
	if err != nil {
		return nil, err
	}
	r11, err := runJSON(a.w11, common...)
	if err != nil {
		return nil, err
	}
	if sval(r10, "checker") != "risu-k1-c3-cert-w10" || sval(r11, "checker") != "risu-k1-c3-cert-w11" {
		return nil, errors.New("inner checker identity")
	}
	if sval(r10, "proof_status") != "ACCEPTED" || sval(r11, "proof_status") != "ACCEPTED" {
		return nil, errors.New("dual Q0 acceptance required")
	}
	for _, k := range []string{"certificate_id", "c2_certificate_id", "c3_source_id", "ordered_trace_map_id", "c2_target_id"} {
		if sval(r10, k) != sval(r11, k) {
			return nil, fmt.Errorf("W10/W11 disagreement:%s", k)
		}
	}
	if nval(r10, "realize_pair_count") != nval(r11, "realize_pair_count") {
		return nil, errors.New("W10/W11 disagreement:realize_pair_count")
	}
	if sval(r10, "certificate_id") != pCID {
		return nil, errors.New("accepted C3 id mismatch")
	}
	if sval(r10, "c2_target_id") != pTarget {
		return nil, errors.New("accepted target mismatch")
	}
	if nval(r10, "realize_pair_count") != len(innerReal) {
		return nil, errors.New("accepted REALIZE count mismatch")
	}

	promoArt := "p:sha256:" + sha256hex(promoRaw)
	eroot := evidenceRoot(claimID, promoArt, pCID, pTarget)

	outerRaw, err := read(a.outer)
	if err != nil {
		return nil, err
	}
	outer, err := strictRaw(outerRaw, "outer")
	if err != nil {
		return nil, err
	}
	if !exactKeys(outer, outerKeys) {
		return nil, errors.New("outer exact-key violation")
	}
	wire, _ := strField(outer, "wire")
	kind, _ := strField(outer, "kind")
	if wire != "risu.k1.w0" || kind != "preservation_certificate" {
		return nil, errors.New("outer wire/kind")
	}
	oClaim, _ := strField(outer, "claim_id")
	if oClaim != claimID {
		return nil, errors.New("outer claim mismatch")
	}
	oTarget, _ := strField(outer, "target_id")
	if oTarget != pTarget {
		return nil, errors.New("outer target mismatch")
	}
	outerReal, err := relation(outer["realize"], "outer.realize")
	if err != nil {
		return nil, err
	}
	if !pairsEqual(outerReal, innerReal) {
		return nil, errors.New("outer REALIZE mismatch")
	}
	var cp proofRef
	if err := json.Unmarshal(outer["closure_proof"], &cp); err != nil {
		return nil, errors.New("outer closure proof")
	}
	if cp.Kind != proofKind || cp.Artifact != promoArt {
		return nil, errors.New("outer closure proof mismatch")
	}
	var gp []grounding
	if err := json.Unmarshal(outer["grounding_proofs"], &gp); err != nil {
		return nil, errors.New("outer grounding")
	}
	if len(gp) != len(innerReal) {
		return nil, errors.New("outer grounding completeness")
	}
	seen := map[string]bool{}
	for _, g := range gp {
		if len(g.Pair) != 2 || !patterns["w"].MatchString(g.Pair[0]) || !patterns["c"].MatchString(g.Pair[1]) {
			return nil, errors.New("outer grounding pair")
		}
		key := g.Pair[0] + "\x00" + g.Pair[1]
		if seen[key] {
			return nil, errors.New("outer grounding duplicate")
		}
		seen[key] = true
		if g.Proof.Kind != proofKind || g.Proof.Artifact != promoArt {
			return nil, errors.New("outer grounding proof mismatch")
		}
	}
	for _, p := range innerReal {
		if !seen[p.W+"\x00"+p.C] {
			return nil, errors.New("outer grounding coverage")
		}
	}
	var roots []string
	if err := json.Unmarshal(outer["evidence_roots"], &roots); err != nil || len(roots) != 1 || roots[0] != eroot {
		return nil, errors.New("outer evidence root mismatch")
	}
	cid, err := outerCertID(outer)
	if err != nil {
		return nil, err
	}
	oCID, _ := strField(outer, "certificate_id")
	if oCID != cid {
		return nil, errors.New("outer certificate_id mismatch")
	}
	return map[string]interface{}{"checker": "risu-k1-c3-promotion-w13", "proof_status": "ACCEPTED", "semantic_claim": "P0_CANDIDATE_MEDIATED_REFINEMENT_COMPOSITION", "authority_created": false, "promotion_artifact_id": promoArt, "outer_certificate_id": cid, "c3_certificate_id": pCID, "c2_target_id": pTarget, "realize_pair_count": len(innerReal)}, nil
}

func main() {
	a := argsT{sources: map[string]string{}}
	flag.StringVar(&a.claim, "claim", "", "")
	flag.StringVar(&a.profile, "profile", "", "")
	flag.StringVar(&a.c3cert, "c3-certificate", "", "")
	flag.StringVar(&a.program, "program", "", "")
	flag.StringVar(&a.c2artifact, "c2-artifact", "", "")
	flag.StringVar(&a.promo, "promotion-artifact", "", "")
	flag.StringVar(&a.outer, "outer-certificate", "", "")
	flag.StringVar(&a.w10, "w10", "", "")
	flag.StringVar(&a.w11, "w11", "", "")
	flag.StringVar(&a.w7, "w7", "", "")
	flag.StringVar(&a.w8, "w8", "", "")
	flag.StringVar(&a.w5, "w5", "", "")
	flag.StringVar(&a.w6, "w6", "", "")
	for _, k := range []string{"w10_source", "w11_source", "w7_model_source", "w7_exec_source", "w7_source", "w8_json_source", "w8_model_source", "w8_exec_source", "w8_source", "w5_source", "w6_source"} {
		v := new(string)
		flag.StringVar(v, k, "", "")
		a.sources[k] = *v
	}
	flag.Parse()
	// flag.StringVar above writes through pointers; reconstruct source values explicitly.
	a.sources["w10_source"] = flag.Lookup("w10_source").Value.String()
	a.sources["w11_source"] = flag.Lookup("w11_source").Value.String()
	a.sources["w7_model_source"] = flag.Lookup("w7_model_source").Value.String()
	a.sources["w7_exec_source"] = flag.Lookup("w7_exec_source").Value.String()
	a.sources["w7_source"] = flag.Lookup("w7_source").Value.String()
	a.sources["w8_json_source"] = flag.Lookup("w8_json_source").Value.String()
	a.sources["w8_model_source"] = flag.Lookup("w8_model_source").Value.String()
	a.sources["w8_exec_source"] = flag.Lookup("w8_exec_source").Value.String()
	a.sources["w8_source"] = flag.Lookup("w8_source").Value.String()
	a.sources["w5_source"] = flag.Lookup("w5_source").Value.String()
	a.sources["w6_source"] = flag.Lookup("w6_source").Value.String()
	out, err := check(a)
	if err != nil {
		out = reject(err.Error())
	}
	enc, _ := json.Marshal(out)
	fmt.Println(string(enc))
}
