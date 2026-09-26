package main

import (
	"bytes"
	"sort"
)

func parseSource(v any, w string) (Source, error) {
	m, e := obj(v, w)
	if e != nil {
		return Source{}, e
	}
	if e = exact(m, "kind", "name"); e != nil {
		return Source{}, rejectf("%s malformed", w)
	}
	k, _ := str(m["kind"], w+".kind")
	n, _ := str(m["name"], w+".name")
	if k != "input" && k != "state" {
		return Source{}, rejectf("%s kind", w)
	}
	if e = token(n, w+".name"); e != nil {
		return Source{}, e
	}
	return Source{k, n}, nil
}

func parseModel(raw []byte, c *Claim) (*Model, error) {
	v, err := parseStrict(raw, "profile")
	if err != nil {
		return nil, err
	}
	p, err := obj(v, "profile")
	if err != nil {
		return nil, err
	}
	if err = exact(p, "wire", "kind", "claim_id", "boundary", "state", "tables", "entry", "blocks"); err != nil {
		return nil, rejectf("profile malformed")
	}
	wire, _ := str(p["wire"], "wire")
	kind, _ := str(p["kind"], "kind")
	cid, _ := str(p["claim_id"], "claim_id")
	if wire != "risu.k1.c3.mfst/v1" || kind != "mediated_finite_state_transducer" || cid != c.ID {
		return nil, rejectf("profile header/claim")
	}
	bd, _ := obj(p["boundary"], "boundary")
	if err = exact(bd, "worlds", "slots"); err != nil {
		return nil, rejectf("boundary malformed")
	}
	worlds, err := stringArray(bd["worlds"], "boundary.worlds", true)
	if err != nil || !sameSet(worlds, c.Worlds) {
		return nil, rejectf("boundary.worlds claim mismatch")
	}
	for _, w := range worlds {
		if !worldRE.MatchString(w) {
			return nil, rejectf("boundary.world")
		}
	}
	sm, err := obj(bd["slots"], "slots")
	if err != nil {
		return nil, err
	}
	slots := map[string][]string{}
	for n, v := range sm {
		if err = token(n, "slot"); err != nil || n == "@world" {
			return nil, rejectf("slot invalid")
		}
		d, err := stringArray(v, "slot."+n, true)
		if err != nil {
			return nil, err
		}
		slots[n] = d
	}
	states := map[string]StateCell{}
	sa, err := arr(p["state"], "state")
	if err != nil {
		return nil, err
	}
	for _, v := range sa {
		m, _ := obj(v, "state")
		if err = exact(m, "name", "domain", "initial"); err != nil {
			return nil, rejectf("state malformed")
		}
		n, _ := str(m["name"], "state.name")
		if err = token(n, "state.name"); err != nil || n == "@world" {
			return nil, rejectf("state name")
		}
		if _, ok := slots[n]; ok {
			return nil, rejectf("state/slot collision")
		}
		if _, ok := states[n]; ok {
			return nil, rejectf("duplicate state")
		}
		d, err := stringArray(m["domain"], "state.domain", true)
		if err != nil {
			return nil, err
		}
		im, _ := obj(m["initial"], "initial")
		k, _ := str(im["kind"], "initial.kind")
		ini := Initial{Kind: k}
		if k == "const" {
			if err = exact(im, "kind", "value"); err != nil {
				return nil, rejectf("initial malformed")
			}
			ini.Value, _ = str(im["value"], "initial.value")
			if !contains(d, ini.Value) {
				return nil, rejectf("initial out of domain")
			}
		} else if k == "input" {
			if err = exact(im, "kind", "name"); err != nil {
				return nil, rejectf("initial malformed")
			}
			ini.Name, _ = str(im["name"], "initial.name")
		} else {
			return nil, rejectf("initial kind")
		}
		states[n] = StateCell{n, d, ini}
	}
	mm := &Model{ClaimID: cid, Worlds: worlds, Slots: slots, States: states, Tables: map[string]Table{}, Blocks: map[string]Block{}}
	sourceDomain := func(s Source) ([]string, error) { return sourceDomainOf(mm, s) }
	for n, st := range states {
		if st.Initial.Kind == "input" {
			d, e := sourceDomain(Source{"input", st.Initial.Name})
			if e != nil || !subset(d, st.Domain) {
				return nil, rejectf("initial domain mismatch:%s", n)
			}
		}
	}
	ta, err := arr(p["tables"], "tables")
	if err != nil {
		return nil, err
	}
	for _, v := range ta {
		tm, _ := obj(v, "table")
		if err = exact(tm, "name", "arguments", "result_domain", "rows"); err != nil {
			return nil, rejectf("table malformed")
		}
		n, _ := str(tm["name"], "table.name")
		if err = token(n, "table.name"); err != nil {
			return nil, err
		}
		if _, ok := mm.Tables[n]; ok {
			return nil, rejectf("duplicate table")
		}
		aa, _ := arr(tm["arguments"], "args")
		args := []Formal{}
		seen := map[string]bool{}
		for _, av := range aa {
			am, _ := obj(av, "formal")
			if err = exact(am, "name", "domain"); err != nil {
				return nil, rejectf("formal malformed")
			}
			an, _ := str(am["name"], "formal.name")
			if err = token(an, "formal.name"); err != nil {
				return nil, err
			}
			if seen[an] {
				return nil, rejectf("duplicate formal")
			}
			seen[an] = true
			ad, err := stringArray(am["domain"], "formal.domain", true)
			if err != nil {
				return nil, err
			}
			args = append(args, Formal{an, ad})
		}
		rd, err := stringArray(tm["result_domain"], "result_domain", true)
		if err != nil {
			return nil, err
		}
		ra, _ := arr(tm["rows"], "rows")
		rows := []Row{}
		lookup := map[string]string{}
		for _, rv := range ra {
			rm, _ := obj(rv, "row")
			if err = exact(rm, "when", "result"); err != nil {
				return nil, rejectf("row malformed")
			}
			wh, err := stringArrayAllowEmpty(rm["when"], "row.when")
			if err != nil || len(wh) != len(args) {
				return nil, rejectf("row arity")
			}
			for i, x := range wh {
				if !contains(args[i].Domain, x) {
					return nil, rejectf("row out of domain")
				}
			}
			res, _ := str(rm["result"], "row.result")
			if !contains(rd, res) {
				return nil, rejectf("row result")
			}
			k := tupleKey(wh)
			if _, ok := lookup[k]; ok {
				return nil, rejectf("duplicate row")
			}
			lookup[k] = res
			rows = append(rows, Row{wh, res})
		}
		exp := cartesianDomains(args)
		if len(exp) != len(lookup) {
			return nil, rejectf("table not total")
		}
		for _, x := range exp {
			if _, ok := lookup[tupleKey(x)]; !ok {
				return nil, rejectf("table not total")
			}
		}
		mm.Tables[n] = Table{n, args, rd, rows, lookup}
	}
	ba, err := arr(p["blocks"], "blocks")
	if err != nil || len(ba) == 0 {
		return nil, rejectf("blocks")
	}
	for _, v := range ba {
		bm, _ := obj(v, "block")
		if err = exact(bm, "label", "ops", "term"); err != nil {
			return nil, rejectf("block malformed")
		}
		lab, _ := str(bm["label"], "label")
		if err = token(lab, "label"); err != nil {
			return nil, err
		}
		if _, ok := mm.Blocks[lab]; ok {
			return nil, rejectf("duplicate block")
		}
		oa, _ := arr(bm["ops"], "ops")
		ops := []Op{}
		for _, ov := range oa {
			o, err := parseOp(ov, mm)
			if err != nil {
				return nil, err
			}
			ops = append(ops, o)
		}
		t, err := parseTerm(bm["term"], mm)
		if err != nil {
			return nil, err
		}
		mm.Blocks[lab] = Block{lab, ops, t}
	}
	entry, _ := str(p["entry"], "entry")
	if err = token(entry, "entry"); err != nil {
		return nil, err
	}
	if _, ok := mm.Blocks[entry]; !ok {
		return nil, rejectf("undefined entry")
	}
	mm.Entry = entry
	for _, b := range mm.Blocks {
		if b.Term.Kind == "GOTO" {
			if _, ok := mm.Blocks[b.Term.Target]; !ok {
				return nil, rejectf("undefined target")
			}
		}
		if b.Term.Kind == "IF_EQ" {
			if _, ok := mm.Blocks[b.Term.True]; !ok {
				return nil, rejectf("undefined target")
			}
			if _, ok := mm.Blocks[b.Term.False]; !ok {
				return nil, rejectf("undefined target")
			}
		}
	}
	return mm, nil
}
func stringArrayAllowEmpty(v any, w string) ([]string, error) {
	a, e := arr(v, w)
	if e != nil {
		return nil, e
	}
	out := []string{}
	for _, x := range a {
		s, e := str(x, w)
		if e != nil {
			return nil, e
		}
		if e = token(s, w); e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, nil
}
func contains(x []string, s string) bool {
	for _, v := range x {
		if v == s {
			return true
		}
	}
	return false
}
func sourceDomainOf(m *Model, s Source) ([]string, error) {
	if s.Kind == "state" {
		x, ok := m.States[s.Name]
		if !ok {
			return nil, rejectf("unknown state source")
		}
		return x.Domain, nil
	}
	if s.Name == "@world" {
		return m.Worlds, nil
	}
	d, ok := m.Slots[s.Name]
	if !ok {
		return nil, rejectf("undeclared input source")
	}
	return d, nil
}
func parseOp(v any, m *Model) (Op, error) {
	o, _ := obj(v, "op")
	ks, _ := str(o["op"], "op.kind")
	z := Op{Kind: ks}
	switch ks {
	case "SET_CONST":
		if err := exact(o, "op", "dst", "value"); err != nil {
			return z, rejectf("SET_CONST malformed")
		}
		z.Dst, _ = str(o["dst"], "dst")
		z.Value, _ = str(o["value"], "value")
		st, ok := m.States[z.Dst]
		if !ok || !contains(st.Domain, z.Value) {
			return z, rejectf("bad SET_CONST")
		}
	case "SET_FROM":
		if err := exact(o, "op", "dst", "source"); err != nil {
			return z, rejectf("SET_FROM malformed")
		}
		z.Dst, _ = str(o["dst"], "dst")
		s, err := parseSource(o["source"], "source")
		if err != nil {
			return z, err
		}
		z.Src = s
		st, ok := m.States[z.Dst]
		d, e := sourceDomainOf(m, s)
		if !ok || e != nil || !subset(d, st.Domain) {
			return z, rejectf("bad SET_FROM")
		}
	case "APPLY_TABLE":
		if err := exact(o, "op", "dst", "table", "arguments"); err != nil {
			return z, rejectf("APPLY_TABLE malformed")
		}
		z.Dst, _ = str(o["dst"], "dst")
		z.Table, _ = str(o["table"], "table")
		st, ok := m.States[z.Dst]
		tb, tok := m.Tables[z.Table]
		aa, ae := arr(o["arguments"], "arguments")
		if !ok || !tok || ae != nil || len(aa) != len(tb.Args) {
			return z, rejectf("bad APPLY_TABLE")
		}
		for i, av := range aa {
			s, e := parseSource(av, "arg")
			if e != nil {
				return z, e
			}
			d, e := sourceDomainOf(m, s)
			if e != nil || !sameSet(d, tb.Args[i].Domain) {
				return z, rejectf("APPLY_TABLE formal domain mismatch")
			}
			z.Args = append(z.Args, s)
		}
		if !subset(tb.ResultDomain, st.Domain) {
			return z, rejectf("APPLY_TABLE result domain")
		}
	case "EMIT_HEX":
		if err := exact(o, "op", "payload"); err != nil {
			return z, rejectf("EMIT malformed")
		}
		z.Payload, _ = str(o["payload"], "payload")
		if !payloadRE.MatchString(z.Payload) {
			return z, rejectf("bad payload")
		}
	default:
		return z, rejectf("unknown/ambient opcode")
	}
	return z, nil
}
func parseTerm(v any, m *Model) (Term, error) {
	o, _ := obj(v, "term")
	k, _ := str(o["op"], "term.op")
	t := Term{Kind: k}
	switch k {
	case "GOTO":
		if err := exact(o, "op", "target"); err != nil {
			return t, rejectf("GOTO malformed")
		}
		t.Target, _ = str(o["target"], "target")
	case "IF_EQ":
		if err := exact(o, "op", "source", "value", "if_true", "if_false"); err != nil {
			return t, rejectf("IF_EQ malformed")
		}
		s, e := parseSource(o["source"], "term.source")
		if e != nil {
			return t, e
		}
		t.Src = s
		t.Value, _ = str(o["value"], "value")
		t.True, _ = str(o["if_true"], "true")
		t.False, _ = str(o["if_false"], "false")
		d, e := sourceDomainOf(m, s)
		if e != nil || !contains(d, t.Value) {
			return t, rejectf("IF_EQ out of domain")
		}
	case "HALT":
		if err := exact(o, "op"); err != nil {
			return t, rejectf("HALT malformed")
		}
	default:
		return t, rejectf("bad terminator")
	}
	return t, nil
}
func cartesianDomains(a []Formal) [][]string {
	out := [][]string{{}}
	for _, f := range a {
		next := [][]string{}
		for _, p := range out {
			for _, v := range f.Domain {
				q := append(append([]string{}, p...), v)
				next = append(next, q)
			}
		}
		out = next
	}
	return out
}
func sourceDesc(s Source) []byte {
	var b bytes.Buffer
	if s.Kind == "input" {
		b.WriteByte('I')
	} else {
		b.WriteByte('S')
	}
	addNet(&b, s.Name)
	return b.Bytes()
}
func semanticID(m *Model) string {
	var b bytes.Buffer
	b.WriteString("RISU-K1-C3-MFST-SEMANTIC-V1\x00")
	b.WriteByte('C')
	addNet(&b, m.ClaimID)
	b.WriteByte('E')
	addNet(&b, m.Entry)
	ws := sortedCopy(m.Worlds)
	b.WriteByte('W')
	addCount(&b, len(ws))
	for _, w := range ws {
		b.WriteByte('w')
		addNet(&b, w)
	}
	sn := sortedKeysSlice(m.Slots)
	b.WriteByte('D')
	addCount(&b, len(sn))
	for _, n := range sn {
		d := sortedCopy(m.Slots[n])
		b.WriteByte('s')
		addNet(&b, n)
		addCount(&b, len(d))
		for _, v := range d {
			b.WriteByte('v')
			addNet(&b, v)
		}
	}
	stn := sortedStateKeys(m.States)
	b.WriteByte('Q')
	addCount(&b, len(stn))
	for _, n := range stn {
		x := m.States[n]
		d := sortedCopy(x.Domain)
		b.WriteByte('q')
		addNet(&b, n)
		addCount(&b, len(d))
		for _, v := range d {
			b.WriteByte('v')
			addNet(&b, v)
		}
		if x.Initial.Kind == "const" {
			b.WriteByte('C')
			addNet(&b, x.Initial.Value)
		} else {
			b.WriteByte('I')
			addNet(&b, x.Initial.Name)
		}
	}
	tn := sortedTableKeys(m.Tables)
	b.WriteByte('T')
	addCount(&b, len(tn))
	for _, n := range tn {
		t := m.Tables[n]
		b.WriteByte('t')
		addNet(&b, n)
		addCount(&b, len(t.Args))
		for _, a := range t.Args {
			b.WriteByte('a')
			addNet(&b, a.Name)
			d := sortedCopy(a.Domain)
			addCount(&b, len(d))
			for _, v := range d {
				b.WriteByte('v')
				addNet(&b, v)
			}
		}
		rd := sortedCopy(t.ResultDomain)
		addCount(&b, len(rd))
		for _, v := range rd {
			b.WriteByte('v')
			addNet(&b, v)
		}
		rows := append([]Row{}, t.Rows...)
		sort.Slice(rows, func(i, j int) bool { return tupleKey(rows[i].When) < tupleKey(rows[j].When) })
		addCount(&b, len(rows))
		for _, r := range rows {
			b.WriteByte('r')
			addCount(&b, len(r.When))
			for _, v := range r.When {
				b.WriteByte('v')
				addNet(&b, v)
			}
			b.WriteByte('o')
			addNet(&b, r.Result)
		}
	}
	bn := sortedBlockKeys(m.Blocks)
	b.WriteByte('B')
	addCount(&b, len(bn))
	for _, n := range bn {
		x := m.Blocks[n]
		b.WriteByte('b')
		addNet(&b, n)
		addCount(&b, len(x.Ops))
		for _, o := range x.Ops {
			switch o.Kind {
			case "SET_CONST":
				b.WriteByte('1')
				addNet(&b, o.Dst)
				addNet(&b, o.Value)
			case "SET_FROM":
				b.WriteByte('2')
				addNet(&b, o.Dst)
				b.Write(sourceDesc(o.Src))
			case "APPLY_TABLE":
				b.WriteByte('3')
				addNet(&b, o.Dst)
				addNet(&b, o.Table)
				addCount(&b, len(o.Args))
				for _, s := range o.Args {
					b.Write(sourceDesc(s))
				}
			case "EMIT_HEX":
				b.WriteByte('4')
				addNet(&b, o.Payload)
			}
		}
		t := x.Term
		switch t.Kind {
		case "GOTO":
			b.WriteByte('G')
			addNet(&b, t.Target)
		case "IF_EQ":
			b.WriteByte('I')
			b.Write(sourceDesc(t.Src))
			addNet(&b, t.Value)
			addNet(&b, t.True)
			addNet(&b, t.False)
		case "HALT":
			b.WriteByte('H')
		}
	}
	return digest("c3sem:sha256:", b.Bytes())
}
func sortedKeysSlice(m map[string][]string) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
func sortedStateKeys(m map[string]StateCell) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
func sortedTableKeys(m map[string]Table) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
func sortedBlockKeys(m map[string]Block) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
