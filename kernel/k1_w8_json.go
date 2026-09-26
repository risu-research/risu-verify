package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
)

var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+$`)
var worldRE = regexp.MustCompile(`^w:sha256:[0-9a-f]{64}$`)
var claimRE = regexp.MustCompile(`^claim:sha256:[0-9a-f]{64}$`)
var consequenceRE = regexp.MustCompile(`^c:sha256:[0-9a-f]{64}$`)
var payloadRE = regexp.MustCompile(`^(?:[0-9a-f]{2})+$`)

type rejectError struct{ s string }

func (e rejectError) Error() string { return e.s }

type unsupportedError struct{ s string }

func (e unsupportedError) Error() string    { return e.s }
func rejectf(f string, a ...any) error      { return rejectError{fmt.Sprintf(f, a...)} }
func unsupportedf(f string, a ...any) error { return unsupportedError{fmt.Sprintf(f, a...)} }

func net(s string) []byte {
	b := []byte(s)
	return []byte(strconv.Itoa(len(b)) + ":" + s + ",")
}
func addNet(b *bytes.Buffer, s string) { b.Write(net(s)) }
func addCount(b *bytes.Buffer, n int)  { addNet(b, strconv.Itoa(n)) }
func digest(prefix string, b []byte) string {
	h := sha256.Sum256(b)
	return prefix + hex.EncodeToString(h[:])
}

func parseStrict(raw []byte, where string) (any, error) {
	if len(raw) == 0 || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return nil, rejectf("%s: empty/BOM", where)
	}
	if bytes.IndexByte(raw, 0) >= 0 || bytes.IndexByte(raw, '\r') >= 0 || bytes.IndexByte(raw, '\t') >= 0 {
		return nil, rejectf("%s: forbidden NUL/CR/TAB", where)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := readJSON(dec, where)
	if err != nil {
		return nil, err
	}
	if _, err = dec.Token(); err != io.EOF {
		if err == nil {
			return nil, rejectf("%s: trailing JSON", where)
		}
		return nil, rejectf("%s: trailing JSON", where)
	}
	return v, nil
}
func readJSON(dec *json.Decoder, where string) (any, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, rejectf("%s: invalid JSON", where)
	}
	switch x := t.(type) {
	case string:
		if bytes.IndexByte([]byte(x), 0) >= 0 || bytes.IndexByte([]byte(x), '\r') >= 0 || bytes.IndexByte([]byte(x), '\t') >= 0 {
			return nil, rejectf("%s: forbidden string", where)
		}
		return x, nil
	case json.Delim:
		if x == '{' {
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, rejectf("%s: object key", where)
				}
				k, ok := kt.(string)
				if !ok {
					return nil, rejectf("%s: object key type", where)
				}
				if _, exists := m[k]; exists {
					return nil, rejectf("%s: duplicate JSON key:%s", where, k)
				}
				v, err := readJSON(dec, where+"."+k)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return nil, rejectf("%s: object close", where)
			}
			return m, nil
		}
		if x == '[' {
			a := []any{}
			i := 0
			for dec.More() {
				v, err := readJSON(dec, fmt.Sprintf("%s[%d]", where, i))
				if err != nil {
					return nil, err
				}
				a = append(a, v)
				i++
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return nil, rejectf("%s: array close", where)
			}
			return a, nil
		}
		return nil, rejectf("%s: unexpected delimiter", where)
	default:
		return nil, rejectf("%s: numbers/booleans/null not admitted", where)
	}
}
func obj(v any, w string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, rejectf("%s: expected object", w)
	}
	return m, nil
}
func arr(v any, w string) ([]any, error) {
	a, ok := v.([]any)
	if !ok {
		return nil, rejectf("%s: expected array", w)
	}
	return a, nil
}
func str(v any, w string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", rejectf("%s: expected string", w)
	}
	return s, nil
}
func exact(m map[string]any, keys ...string) error {
	if len(m) != len(keys) {
		return rejectf("malformed object")
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return rejectf("malformed object")
		}
	}
	return nil
}
func token(s, w string) error {
	if !tokenRE.MatchString(s) {
		return rejectf("%s: noncanonical token", w)
	}
	return nil
}
func stringArray(v any, w string, nonempty bool) ([]string, error) {
	a, err := arr(v, w)
	if err != nil {
		return nil, err
	}
	if nonempty && len(a) == 0 {
		return nil, rejectf("%s: empty domain", w)
	}
	out := make([]string, 0, len(a))
	seen := map[string]bool{}
	for i, x := range a {
		s, err := str(x, fmt.Sprintf("%s[%d]", w, i))
		if err != nil {
			return nil, err
		}
		if err = token(s, w); err != nil {
			return nil, err
		}
		if seen[s] {
			return nil, rejectf("%s: duplicate", w)
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}
func sortedCopy(x []string) []string { y := append([]string{}, x...); sort.Strings(y); return y }
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := sortedCopy(a)
	y := sortedCopy(b)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
func subset(a, b []string) bool {
	mb := map[string]bool{}
	for _, x := range b {
		mb[x] = true
	}
	for _, x := range a {
		if !mb[x] {
			return false
		}
	}
	return true
}

type pair struct{ W, C string }

type Claim struct {
	ID     string
	Worlds []string
	Allow  map[pair]bool
}

func claimID(m map[string]any) (string, error) {
	sem, err := str(m["semantics"], "claim.semantics")
	if err != nil {
		return "", err
	}
	ws, err := stringArray(m["worlds"], "claim.worlds", true)
	if err != nil {
		return "", err
	}
	aa, err := arr(m["allow"], "claim.allow")
	if err != nil {
		return "", err
	}
	ps := []pair{}
	for _, v := range aa {
		r, err := arr(v, "claim.allow.row")
		if err != nil || len(r) != 2 {
			return "", rejectf("claim.allow row")
		}
		w, _ := str(r[0], "w")
		c, _ := str(r[1], "c")
		ps = append(ps, pair{w, c})
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].W == ps[j].W {
			return ps[i].C < ps[j].C
		}
		return ps[i].W < ps[j].W
	})
	var b bytes.Buffer
	b.WriteString("RISU-K1-CLAIM-W0\x00")
	b.WriteByte('S')
	addNet(&b, sem)
	b.WriteByte('W')
	addCount(&b, len(ws))
	for _, w := range sortedCopy(ws) {
		b.WriteByte('V')
		addNet(&b, w)
	}
	b.WriteByte('A')
	addCount(&b, len(ps))
	for _, p := range ps {
		b.WriteByte('P')
		addNet(&b, p.W)
		addNet(&b, p.C)
	}
	return digest("claim:sha256:", b.Bytes()), nil
}
func parseClaim(raw []byte) (*Claim, error) {
	v, err := parseStrict(raw, "claim")
	if err != nil {
		return nil, err
	}
	m, err := obj(v, "claim")
	if err != nil {
		return nil, err
	}
	if err = exact(m, "wire", "kind", "semantics", "worlds", "allow", "claim_id"); err != nil {
		return nil, rejectf("claim: malformed")
	}
	wire, _ := str(m["wire"], "wire")
	kind, _ := str(m["kind"], "kind")
	sem, _ := str(m["semantics"], "sem")
	if wire != "risu.k1.w0" || kind != "claim" || sem != "safety-subset-v1" {
		return nil, rejectf("claim: unsupported")
	}
	ws, err := stringArray(m["worlds"], "claim.worlds", true)
	if err != nil {
		return nil, err
	}
	for _, w := range ws {
		if !worldRE.MatchString(w) {
			return nil, rejectf("claim.world")
		}
	}
	allowA, err := arr(m["allow"], "claim.allow")
	if err != nil || len(allowA) == 0 {
		return nil, rejectf("claim.allow")
	}
	allow := map[pair]bool{}
	worldSet := map[string]bool{}
	for _, w := range ws {
		worldSet[w] = true
	}
	for _, v := range allowA {
		r, err := arr(v, "claim.allow.row")
		if err != nil || len(r) != 2 {
			return nil, rejectf("claim.allow row")
		}
		w, _ := str(r[0], "w")
		c, _ := str(r[1], "c")
		if !worldSet[w] || !consequenceRE.MatchString(c) {
			return nil, rejectf("claim.allow pair")
		}
		p := pair{w, c}
		if allow[p] {
			return nil, rejectf("claim.allow duplicate")
		}
		allow[p] = true
	}
	for _, w := range ws {
		found := false
		for p := range allow {
			if p.W == w {
				found = true
				break
			}
		}
		if !found {
			return nil, rejectf("claim.allow uncovered world")
		}
	}
	id, err := str(m["claim_id"], "claim_id")
	if err != nil || !claimRE.MatchString(id) {
		return nil, rejectf("claim.claim_id")
	}
	cid, err := claimID(m)
	if err != nil || cid != id {
		return nil, rejectf("claim.claim_id mismatch")
	}
	return &Claim{ID: id, Worlds: ws, Allow: allow}, nil
}

type Source struct{ Kind, Name string }
type Initial struct{ Kind, Value, Name string }
type StateCell struct {
	Name    string
	Domain  []string
	Initial Initial
}
type Formal struct {
	Name   string
	Domain []string
}
type Row struct {
	When   []string
	Result string
}
type Table struct {
	Name         string
	Args         []Formal
	ResultDomain []string
	Rows         []Row
	Lookup       map[string]string
}
type Op struct {
	Kind, Dst, Value, Table, Payload string
	Src                              Source
	Args                             []Source
}
type Term struct {
	Kind, Target, Value, True, False string
	Src                              Source
}
type Block struct {
	Label string
	Ops   []Op
	Term  Term
}
type Model struct {
	ClaimID string
	Worlds  []string
	Slots   map[string][]string
	States  map[string]StateCell
	Tables  map[string]Table
	Blocks  map[string]Block
	Entry   string
}

func tupleKey(x []string) string { return stringsJoinZero(x) }
func stringsJoinZero(x []string) string {
	var b bytes.Buffer
	for i, s := range x {
		if i > 0 {
			b.WriteByte(0)
		}
		b.WriteString(s)
	}
	return b.String()
}
