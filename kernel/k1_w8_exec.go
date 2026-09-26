package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const c2MaxBytes = 65536
const c2MaxGas = 10000

type Point map[string]string
type Node struct {
	Label     string
	State     []string
	Effects   []string
	Halt      bool
	SuccLabel string
	SuccState []string
}
type TraceEntry struct {
	Point    Point
	Payloads []string
}
type RunSet struct {
	Traces   []TraceEntry
	Relation map[pair]bool
	GraphID  string
	TraceID  string
}

func allPoints(m *Model) []Point {
	names := sortedKeysSlice(m.Slots)
	rows := [][]string{{}}
	for _, n := range names {
		next := [][]string{}
		for _, r := range rows {
			for _, v := range sortedCopy(m.Slots[n]) {
				q := append(append([]string{}, r...), v)
				next = append(next, q)
			}
		}
		rows = next
	}
	out := []Point{}
	for _, w := range sortedCopy(m.Worlds) {
		for _, r := range rows {
			p := Point{"@world": w}
			for i, n := range names {
				p[n] = r[i]
			}
			out = append(out, p)
		}
	}
	return out
}
func pointEncoding(p Point, names []string) []byte {
	var b bytes.Buffer
	b.WriteByte('P')
	addNet(&b, p["@world"])
	addCount(&b, len(names))
	for _, n := range names {
		b.WriteByte('s')
		addNet(&b, n)
		addNet(&b, p[n])
	}
	return b.Bytes()
}
func readSource(s Source, p Point, q map[string]string) (string, error) {
	if s.Kind == "state" {
		v, ok := q[s.Name]
		if !ok {
			return "", rejectf("missing state")
		}
		return v, nil
	}
	v, ok := p[s.Name]
	if !ok {
		return "", rejectf("missing input")
	}
	return v, nil
}
func consequence(payload string) string {
	raw, _ := hex.DecodeString(payload)
	b := append([]byte("RISU-K1-CAPSULE-CONSEQUENCE-V1\x00"), raw...)
	return digest("c:sha256:", b)
}
func stateTupleKey(label string, state []string) string {
	return label + "\xff" + stringsJoinZero(state)
}
func executeMFST(m *Model) (*RunSet, error) {
	stateNames := sortedStateKeys(m.States)
	slotNames := sortedKeysSlice(m.Slots)
	rs := &RunSet{Relation: map[pair]bool{}}
	var graph bytes.Buffer
	graph.WriteString("RISU-K1-C3-MFST-GRAPH-V1\x00")
	var trace bytes.Buffer
	trace.WriteString("RISU-K1-C3-MFST-TRACE-V1\x00")
	for _, p := range allPoints(m) {
		q := map[string]string{}
		for _, n := range stateNames {
			st := m.States[n]
			if st.Initial.Kind == "const" {
				q[n] = st.Initial.Value
			} else {
				q[n] = p[st.Initial.Name]
			}
		}
		label := m.Entry
		seen := map[string]bool{}
		nodes := []Node{}
		payloads := []string{}
		for {
			sv := make([]string, len(stateNames))
			for i, n := range stateNames {
				sv[i] = q[n]
			}
			key := stateTupleKey(label, sv)
			if seen[key] {
				return nil, rejectf("MFST closure incomplete: repeated configuration")
			}
			seen[key] = true
			block := m.Blocks[label]
			local := []string{}
			for _, o := range block.Ops {
				switch o.Kind {
				case "SET_CONST":
					q[o.Dst] = o.Value
				case "SET_FROM":
					v, e := readSource(o.Src, p, q)
					if e != nil {
						return nil, e
					}
					q[o.Dst] = v
				case "APPLY_TABLE":
					args := make([]string, len(o.Args))
					for i, s := range o.Args {
						v, e := readSource(s, p, q)
						if e != nil {
							return nil, e
						}
						args[i] = v
					}
					tb := m.Tables[o.Table]
					r, ok := tb.Lookup[tupleKey(args)]
					if !ok {
						return nil, rejectf("table lookup hole")
					}
					q[o.Dst] = r
				case "EMIT_HEX":
					local = append(local, o.Payload)
					payloads = append(payloads, o.Payload)
				}
			}
			t := block.Term
			if t.Kind == "HALT" {
				nodes = append(nodes, Node{Label: label, State: append([]string{}, sv...), Effects: local, Halt: true})
				break
			}
			var next string
			if t.Kind == "GOTO" {
				next = t.Target
			} else {
				v, e := readSource(t.Src, p, q)
				if e != nil {
					return nil, e
				}
				if v == t.Value {
					next = t.True
				} else {
					next = t.False
				}
			}
			ss := make([]string, len(stateNames))
			for i, n := range stateNames {
				ss[i] = q[n]
			}
			nodes = append(nodes, Node{Label: label, State: append([]string{}, sv...), Effects: local, SuccLabel: next, SuccState: ss})
			label = next
		}
		if len(payloads) == 0 {
			return nil, rejectf("MFST closure incomplete: zero-effect HALT")
		}
		for _, h := range payloads {
			rs.Relation[pair{p["@world"], consequence(h)}] = true
		}
		cp := Point{}
		for k, v := range p {
			cp[k] = v
		}
		rs.Traces = append(rs.Traces, TraceEntry{cp, append([]string{}, payloads...)})
		sort.Slice(nodes, func(i, j int) bool {
			if nodes[i].Label != nodes[j].Label {
				return nodes[i].Label < nodes[j].Label
			}
			return stringsJoinZero(nodes[i].State) < stringsJoinZero(nodes[j].State)
		})
		graph.Write(pointEncoding(p, slotNames))
		addCount(&graph, len(nodes))
		for _, n := range nodes {
			graph.WriteByte('N')
			addNet(&graph, n.Label)
			writeStateTuple(&graph, stateNames, n.State)
			addCount(&graph, len(n.Effects))
			for _, h := range n.Effects {
				graph.WriteByte('e')
				addNet(&graph, h)
			}
			if n.Halt {
				graph.WriteByte('H')
			} else {
				graph.WriteByte('S')
				addNet(&graph, n.SuccLabel)
				writeStateTuple(&graph, stateNames, n.SuccState)
			}
		}
		trace.Write(pointEncoding(p, slotNames))
		addCount(&trace, len(payloads))
		for _, h := range payloads {
			trace.WriteByte('e')
			addNet(&trace, h)
		}
	}
	rs.GraphID = digest("c3graph:sha256:", graph.Bytes())
	rs.TraceID = digest("c3trace:sha256:", trace.Bytes())
	return rs, nil
}
func writeStateTuple(b *bytes.Buffer, names, vals []string) {
	addCount(b, len(names))
	for i, n := range names {
		addNet(b, n)
		addNet(b, vals[i])
	}
}
func c2Label(depth int, path []int, total int) string {
	if depth == 0 {
		return "C3N.ROOT"
	}
	p := make([]string, len(path))
	for i, x := range path {
		p[i] = strconv.Itoa(x)
	}
	if depth == total {
		return "C3L." + strings.Join(p, ".")
	}
	return "C3N." + strings.Join(p, ".")
}
func c2Program(m *Model, traces []TraceEntry) ([]byte, error) {
	dims := []string{"@world"}
	dims = append(dims, sortedKeysSlice(m.Slots)...)
	dom := [][]string{sortedCopy(m.Worlds)}
	for _, n := range sortedKeysSlice(m.Slots) {
		dom = append(dom, sortedCopy(m.Slots[n]))
	}
	tm := map[string][]string{}
	for _, te := range traces {
		vals := make([]string, len(dims))
		for i, d := range dims {
			vals[i] = te.Point[d]
		}
		tm[tupleKey(vals)] = te.Payloads
	}
	lines := []string{}
	var rec func(int, []int, []string) error
	rec = func(d int, path []int, vals []string) error {
		lines = append(lines, "LABEL "+c2Label(d, path, len(dims)))
		if d == len(dims) {
			t, ok := tm[tupleKey(vals)]
			if !ok {
				return rejectf("normal form missing point")
			}
			for _, h := range t {
				lines = append(lines, "EMIT_HEX "+h)
			}
			lines = append(lines, "HALT")
			return nil
		}
		for i, v := range dom[d] {
			np := append(append([]int{}, path...), i)
			lines = append(lines, fmt.Sprintf("IF_EQ %s %s %s", dims[d], v, c2Label(d+1, np, len(dims))))
		}
		lines = append(lines, "GOTO C3.TRAP")
		for i, v := range dom[d] {
			np := append(append([]int{}, path...), i)
			nv := append(append([]string{}, vals...), v)
			if e := rec(d+1, np, nv); e != nil {
				return e
			}
		}
		return nil
	}
	if e := rec(0, nil, nil); e != nil {
		return nil, e
	}
	lines = append(lines, "LABEL C3.TRAP", "GOTO C3.TRAP")
	raw := []byte(strings.Join(lines, "\n") + "\n")
	if len(raw) > c2MaxBytes {
		return nil, unsupportedf("CBTNF-v1 exceeds C2 program byte limit")
	}
	return raw, nil
}

type C2Ins struct{ Op, A, B, C string }

func parseC2(raw []byte) ([]C2Ins, map[string]int, error) {
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	ins := []C2Ins{}
	labs := map[string]int{}
	refs := []string{}
	for _, line := range lines {
		p := strings.Split(line, " ")
		if len(p) == 0 {
			return nil, nil, rejectf("C2 empty")
		}
		switch p[0] {
		case "LABEL":
			if len(p) != 2 {
				return nil, nil, rejectf("C2 LABEL")
			}
			if _, ok := labs[p[1]]; ok {
				return nil, nil, rejectf("C2 duplicate label")
			}
			labs[p[1]] = len(ins)
			ins = append(ins, C2Ins{Op: "LABEL", A: p[1]})
		case "IF_EQ":
			if len(p) != 4 {
				return nil, nil, rejectf("C2 IF")
			}
			refs = append(refs, p[3])
			ins = append(ins, C2Ins{Op: "IF_EQ", A: p[1], B: p[2], C: p[3]})
		case "GOTO":
			if len(p) != 2 {
				return nil, nil, rejectf("C2 GOTO")
			}
			refs = append(refs, p[1])
			ins = append(ins, C2Ins{Op: "GOTO", A: p[1]})
		case "EMIT_HEX":
			if len(p) != 2 {
				return nil, nil, rejectf("C2 EMIT")
			}
			ins = append(ins, C2Ins{Op: "EMIT_HEX", A: p[1]})
		case "HALT":
			if len(p) != 1 {
				return nil, nil, rejectf("C2 HALT")
			}
			ins = append(ins, C2Ins{Op: "HALT"})
		default:
			return nil, nil, rejectf("C2 opcode")
		}
	}
	for _, r := range refs {
		if _, ok := labs[r]; !ok {
			return nil, nil, rejectf("C2 undefined label")
		}
	}
	return ins, labs, nil
}
func replayC2(raw []byte, m *Model) ([]TraceEntry, int, error) {
	ins, labs, e := parseC2(raw)
	if e != nil {
		return nil, 0, e
	}
	out := []TraceEntry{}
	maxGas := 0
	for _, p := range allPoints(m) {
		pc := 0
		tr := []string{}
		steps := 0
		for {
			if steps >= c2MaxGas {
				return nil, 0, unsupportedf("CBTNF-v1 exceeds C2 gas limit")
			}
			if pc < 0 || pc >= len(ins) {
				return nil, 0, rejectf("C2 falloff")
			}
			x := ins[pc]
			steps++
			switch x.Op {
			case "LABEL":
				pc++
			case "IF_EQ":
				if p[x.A] == x.B {
					pc = labs[x.C]
				} else {
					pc++
				}
			case "GOTO":
				pc = labs[x.A]
			case "EMIT_HEX":
				tr = append(tr, x.A)
				pc++
			case "HALT":
				goto done
			}
		}
	done:
		if len(tr) == 0 {
			return nil, 0, rejectf("C2 zero trace")
		}
		if steps > maxGas {
			maxGas = steps
		}
		cp := Point{}
		for k, v := range p {
			cp[k] = v
		}
		out = append(out, TraceEntry{cp, tr})
	}
	return out, maxGas, nil
}
func tracesEqual(a, b []TraceEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i].Point) != len(b[i].Point) || len(a[i].Payloads) != len(b[i].Payloads) {
			return false
		}
		for k, v := range a[i].Point {
			if b[i].Point[k] != v {
				return false
			}
		}
		for j := range a[i].Payloads {
			if a[i].Payloads[j] != b[i].Payloads[j] {
				return false
			}
		}
	}
	return true
}
func c2Artifact(m *Model, claimID string, prog []byte, gas int) ([]byte, string, error) {
	h := sha256.Sum256(prog)
	slots := map[string]any{}
	for _, n := range sortedKeysSlice(m.Slots) {
		slots[n] = sortedCopy(m.Slots[n])
	}
	o := map[string]any{"boundary": map[string]any{"gas": gas, "slots": slots, "worlds": sortedCopy(m.Worlds)}, "capsule_semantics": "risu.k1.capsule/v1", "claim_id": claimID, "program_sha256": hex.EncodeToString(h[:]), "proof_format": "k1.capsule-closure/v1"}
	raw, e := json.Marshal(o)
	if e != nil {
		return nil, "", e
	}
	return raw, digest("p:sha256:", raw), nil
}
func c2Target(programSHA string, m *Model, gas int, rel map[pair]bool) string {
	var b bytes.Buffer
	b.WriteString("RISU-K1-TARGET-CAPSULE-V1\x00")
	b.WriteByte('S')
	addNet(&b, "risu.k1.capsule/v1")
	b.WriteByte('P')
	addNet(&b, programSHA)
	b.WriteByte('G')
	addNet(&b, strconv.Itoa(gas))
	ws := sortedCopy(m.Worlds)
	b.WriteByte('W')
	addNet(&b, strconv.Itoa(len(ws)))
	for _, w := range ws {
		b.WriteByte('w')
		addNet(&b, w)
	}
	ns := sortedKeysSlice(m.Slots)
	b.WriteByte('D')
	addNet(&b, strconv.Itoa(len(ns)))
	for _, n := range ns {
		d := sortedCopy(m.Slots[n])
		b.WriteByte('s')
		addNet(&b, n)
		addNet(&b, strconv.Itoa(len(d)))
		for _, v := range d {
			b.WriteByte('v')
			addNet(&b, v)
		}
	}
	rr := make([]pair, 0, len(rel))
	for p := range rel {
		rr = append(rr, p)
	}
	sort.Slice(rr, func(i, j int) bool {
		if rr[i].W == rr[j].W {
			return rr[i].C < rr[j].C
		}
		return rr[i].W < rr[j].W
	})
	b.WriteByte('R')
	addNet(&b, strconv.Itoa(len(rr)))
	for _, p := range rr {
		b.WriteByte('r')
		addNet(&b, p.W)
		addNet(&b, p.C)
	}
	return digest("t:sha256:", b.Bytes())
}
func programSHA(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
