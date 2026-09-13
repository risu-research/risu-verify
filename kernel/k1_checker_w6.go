package main

// RISU K1 checker W6 independently checks k1.capsule-closure/v1.
// It uses only the Go standard library, imports no RISU checker code, executes
// no Python, and derives the complete capsule REALIZE relation itself.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	proofKind        = "k1.capsule-closure/v1"
	capsuleSemantics = "risu.k1.capsule/v1"
	maxProgramBytes  = 65536
	maxGas           = 10000
)

type rejectError struct{ msg string }
func (e rejectError) Error() string { return e.msg }
type unsupportedError struct{ msg string }
func (e unsupportedError) Error() string { return e.msg }
func reject(s string) error { return rejectError{s} }
func unsupported(s string) error { return unsupportedError{s} }

var idRE = map[string]*regexp.Regexp{
	"w": regexp.MustCompile(`^w:sha256:[0-9a-f]{64}$`),
	"c": regexp.MustCompile(`^c:sha256:[0-9a-f]{64}$`),
	"t": regexp.MustCompile(`^t:sha256:[0-9a-f]{64}$`),
	"p": regexp.MustCompile(`^p:sha256:[0-9a-f]{64}$`),
	"e": regexp.MustCompile(`^e:sha256:[0-9a-f]{64}$`),
	"claim": regexp.MustCompile(`^claim:sha256:[0-9a-f]{64}$`),
	"cert": regexp.MustCompile(`^cert:sha256:[0-9a-f]{64}$`),
}
var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+$`)
var hexRE = regexp.MustCompile(`^(?:[0-9a-f]{2})+$`)
var proofKindRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)

var forbiddenAmbient = map[string]bool{"CLOCK":true,"RNG":true,"FILE":true,"NET":true,"HOSTCALL":true,"SPAWN":true}
var allowedOps = map[string]bool{"LABEL":true,"IF_EQ":true,"GOTO":true,"EMIT_HEX":true,"HALT":true}

type Pair struct{ W, C string }
type ProofRef struct { Kind string `json:"kind"`; Artifact string `json:"artifact"` }
type GroundEntry struct { Pair [2]string `json:"pair"`; Proof ProofRef `json:"proof"` }
type Claim struct {
	Wire string `json:"wire"`; Kind string `json:"kind"`; Semantics string `json:"semantics"`
	Worlds []string `json:"worlds"`; Allow [][]string `json:"allow"`; ClaimID string `json:"claim_id"`
}
type Certificate struct {
	Wire string `json:"wire"`; Kind string `json:"kind"`; ClaimID string `json:"claim_id"`; TargetID string `json:"target_id"`
	Realize [][]string `json:"realize"`; ClosureProof ProofRef `json:"closure_proof"`; GroundingProofs []GroundEntry `json:"grounding_proofs"`
	EvidenceRoots []string `json:"evidence_roots"`; CertificateID string `json:"certificate_id"`
}
type Boundary struct { Worlds []string `json:"worlds"`; Slots map[string][]string `json:"slots"`; Gas int `json:"gas"` }
type Artifact struct {
	ProofFormat string `json:"proof_format"`; ClaimID string `json:"claim_id"`; CapsuleSemantics string `json:"capsule_semantics"`
	ProgramSHA256 string `json:"program_sha256"`; Boundary Boundary `json:"boundary"`
}
type Instr struct { Op, A, B, C string; Payload []byte }
type Result map[string]any

func exactObject(raw []byte, expected []string, where string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil { return nil, reject(where+": malformed object") }
	if len(m) != len(expected) { return nil, reject(where+": malformed object") }
	for _, k := range expected { if _, ok := m[k]; !ok { return nil, reject(where+": malformed object") } }
	return m, nil
}
func decodeExact(raw []byte, expected []string, where string, out any) (map[string]json.RawMessage, error) {
	m, err := exactObject(raw, expected, where); if err != nil { return nil, err }
	if err := json.Unmarshal(raw, out); err != nil { return nil, reject(where+": malformed object") }
	return m, nil
}
func ident(kind, value, where string) error {
	r, ok := idRE[kind]; if !ok || !r.MatchString(value) { return reject(where+": noncanonical identifier") }; return nil
}
func net(s string) []byte { return []byte(strconv.Itoa(len([]byte(s)))+":"+s+",") }
func vals(tag string, xs []string) []byte {
	var b bytes.Buffer; b.WriteString(tag); b.Write(net(strconv.Itoa(len(xs))))
	for _, x := range xs { b.WriteByte('V'); b.Write(net(x)) }; return b.Bytes()
}
func sortedPairs(xs []Pair) []Pair {
	out := append([]Pair(nil), xs...); sort.Slice(out, func(i,j int) bool { if out[i].W != out[j].W { return out[i].W < out[j].W }; return out[i].C < out[j].C }); return out
}
func pairsTranscript(tag string, xs []Pair) []byte {
	rows := sortedPairs(xs); var b bytes.Buffer; b.WriteString(tag); b.Write(net(strconv.Itoa(len(rows))))
	for _, p := range rows { b.WriteByte('P'); b.Write(net(p.W)); b.Write(net(p.C)) }; return b.Bytes()
}
func parsePair(row []string, where string) (Pair,error) {
	if len(row)!=2 { return Pair{}, reject(where+": expected pair") }
	if err:=ident("w",row[0],where+".world"); err!=nil{return Pair{},err}; if err:=ident("c",row[1],where+".consequence");err!=nil{return Pair{},err}
	return Pair{row[0],row[1]},nil
}
func parseRelation(rows [][]string, where string) ([]Pair,error) {
	out:=make([]Pair,0,len(rows)); seen:=map[Pair]bool{}
	for i,row:=range rows { p,err:=parsePair(row,fmt.Sprintf("%s[%d]",where,i)); if err!=nil{return nil,err}; if seen[p]{return nil,reject(where+": duplicate pair")}; seen[p]=true; out=append(out,p) }
	return out,nil
}
func pairSet(xs []Pair) map[Pair]bool { m:=map[Pair]bool{}; for _,p:=range xs{m[p]=true}; return m }
func equalPairSets(a,b []Pair) bool { aa,bb:=pairSet(a),pairSet(b); if len(aa)!=len(bb){return false}; for p:=range aa{if !bb[p]{return false}}; return true }

func claimID(c Claim, allow []Pair) string {
	ws:=append([]string(nil),c.Worlds...); sort.Strings(ws); var b bytes.Buffer
	b.Write([]byte("RISU-K1-CLAIM-W0\x00")); b.WriteByte('S'); b.Write(net(c.Semantics)); b.Write(vals("W",ws)); b.Write(pairsTranscript("A",allow))
	h:=sha256.Sum256(b.Bytes()); return "claim:sha256:"+hex.EncodeToString(h[:])
}
func checkClaim(raw []byte) (Claim,[]Pair,map[string]bool,error) {
	var c Claim; _,err:=decodeExact(raw,[]string{"wire","kind","semantics","worlds","allow","claim_id"},"claim",&c); if err!=nil{return c,nil,nil,err}
	if c.Wire!="risu.k1.w0"||c.Kind!="claim"||c.Semantics!="safety-subset-v1"{return c,nil,nil,reject("claim: unsupported wire/semantics")}
	if len(c.Worlds)==0{return c,nil,nil,reject("claim.worlds: empty")}; worlds:=map[string]bool{}
	for _,w:=range c.Worlds{if err:=ident("w",w,"claim.world");err!=nil{return c,nil,nil,err};if worlds[w]{return c,nil,nil,reject("claim.worlds: duplicate")};worlds[w]=true}
	allow,err:=parseRelation(c.Allow,"claim.allow");if err!=nil{return c,nil,nil,err};if len(allow)==0{return c,nil,nil,reject("claim.allow: empty")}
	has:=map[string]bool{};for _,p:=range allow{if !worlds[p.W]{return c,nil,nil,reject("claim.allow: undeclared world")};has[p.W]=true};for w:=range worlds{if !has[w]{return c,nil,nil,reject("claim.allow: world without allowed consequence")}}
	if err:=ident("claim",c.ClaimID,"claim.claim_id");err!=nil{return c,nil,nil,err};if c.ClaimID!=claimID(c,allow){return c,nil,nil,reject("claim.claim_id: mismatch")}
	return c,allow,worlds,nil
}

func validateProofRefRaw(raw []byte, where string) (ProofRef,error) {
	var p ProofRef; _,err:=decodeExact(raw,[]string{"kind","artifact"},where,&p);if err!=nil{return p,err};if !proofKindRE.MatchString(p.Kind){return p,reject(where+".kind: noncanonical proof kind")};if err:=ident("p",p.Artifact,where+".artifact");err!=nil{return p,err};return p,nil
}
func validateCertNested(top map[string]json.RawMessage) error {
	if _,err:=validateProofRefRaw(top["closure_proof"],"certificate.closure_proof");err!=nil{return err}
	var rows []json.RawMessage;if err:=json.Unmarshal(top["grounding_proofs"],&rows);err!=nil{return reject("certificate.grounding_proofs: malformed")}
	for i,raw:=range rows{var e GroundEntry;m,err:=decodeExact(raw,[]string{"pair","proof"},fmt.Sprintf("certificate.grounding_proofs[%d]",i),&e);if err!=nil{return err};if _,err:=parsePair(e.Pair[:],fmt.Sprintf("certificate.grounding_proofs[%d].pair",i));err!=nil{return err};if _,err:=validateProofRefRaw(m["proof"],fmt.Sprintf("certificate.grounding_proofs[%d].proof",i));err!=nil{return err}}
	return nil
}

type GroundBind struct{W,C,Kind,Artifact string}
func certificateID(c Certificate, realize []Pair) string {
	gs:=make([]GroundBind,0,len(c.GroundingProofs));for _,g:=range c.GroundingProofs{gs=append(gs,GroundBind{g.Pair[0],g.Pair[1],g.Proof.Kind,g.Proof.Artifact})}
	sort.Slice(gs,func(i,j int)bool{a,b:=gs[i],gs[j];if a.W!=b.W{return a.W<b.W};if a.C!=b.C{return a.C<b.C};if a.Kind!=b.Kind{return a.Kind<b.Kind};return a.Artifact<b.Artifact})
	roots:=append([]string(nil),c.EvidenceRoots...);sort.Strings(roots);var b bytes.Buffer;b.Write([]byte("RISU-K1-CERT-W0\x00"));b.WriteByte('C');b.Write(net(c.ClaimID));b.WriteByte('T');b.Write(net(c.TargetID));b.Write(pairsTranscript("R",realize));b.WriteByte('Q');b.Write(net(c.ClosureProof.Kind));b.Write(net(c.ClosureProof.Artifact));b.WriteByte('G');b.Write(net(strconv.Itoa(len(gs))));for _,g:=range gs{b.WriteByte('g');b.Write(net(g.W));b.Write(net(g.C));b.Write(net(g.Kind));b.Write(net(g.Artifact))};b.Write(vals("E",roots));h:=sha256.Sum256(b.Bytes());return "cert:sha256:"+hex.EncodeToString(h[:])
}

func strictLines(raw []byte) ([]string,error) {
	if len(raw)==0||len(raw)>maxProgramBytes{return nil,reject("capsule program: invalid size")};if !json.Valid([]byte(strconv.Quote(string(raw)))){ /* UTF-8 checked below */ }
	if !utf8Valid(raw){return nil,reject("capsule program: invalid UTF-8")};text:=string(raw);if strings.ContainsRune(text,'\x00')||strings.Contains(text,"\r")||strings.Contains(text,"\t"){return nil,reject("capsule program: ambiguous bytes")}
	lines:=strings.Split(text,"\n");if len(lines)>0&&lines[len(lines)-1]==""{lines=lines[:len(lines)-1]};if len(lines)==0{return nil,reject("capsule program: empty line")}
	for _,line:=range lines{if line==""{return nil,reject("capsule program: empty line")};if strings.TrimSpace(line)!=line||strings.Contains(line,"  "){return nil,reject("capsule program: noncanonical spacing")}}
	return lines,nil
}
func utf8Valid(raw []byte) bool { return strings.ToValidUTF8(string(raw), "\ufffd") == string(raw) }

func parseProgram(raw []byte)([]Instr,map[string]int,error){
	lines,err:=strictLines(raw);if err!=nil{return nil,nil,err};ins:=make([]Instr,0,len(lines));labels:=map[string]int{};refs:=[]string{}
	for idx,line:=range lines{parts:=strings.Split(line," ");op:=parts[0];if forbiddenAmbient[op]{return nil,nil,reject("capsule program: ambient capability forbidden:"+op)};if !allowedOps[op]{return nil,nil,reject("capsule program: unknown opcode:"+op)}
		switch op{
		case "LABEL": if len(parts)!=2||!tokenRE.MatchString(parts[1]){return nil,nil,reject("capsule program: label syntax")};if _,ok:=labels[parts[1]];ok{return nil,nil,reject("capsule program: duplicate label")};labels[parts[1]]=idx;ins=append(ins,Instr{Op:op,A:parts[1]})
		case "IF_EQ": if len(parts)!=4||!tokenRE.MatchString(parts[1])||!tokenRE.MatchString(parts[2])||!tokenRE.MatchString(parts[3]){return nil,nil,reject("capsule program: IF_EQ syntax")};refs=append(refs,parts[3]);ins=append(ins,Instr{Op:op,A:parts[1],B:parts[2],C:parts[3]})
		case "GOTO": if len(parts)!=2||!tokenRE.MatchString(parts[1]){return nil,nil,reject("capsule program: GOTO syntax")};refs=append(refs,parts[1]);ins=append(ins,Instr{Op:op,A:parts[1]})
		case "EMIT_HEX": if len(parts)!=2||!hexRE.MatchString(parts[1]){return nil,nil,reject("capsule program: EMIT_HEX syntax")};payload,e:=hex.DecodeString(parts[1]);if e!=nil{return nil,nil,reject("capsule program: EMIT_HEX syntax")};ins=append(ins,Instr{Op:op,Payload:payload})
		case "HALT": if len(parts)!=1{return nil,nil,reject("capsule program: HALT syntax")};ins=append(ins,Instr{Op:op})}
	}
	for _,r:=range refs{if _,ok:=labels[r];!ok{return nil,nil,reject("capsule program: undefined label")}};return ins,labels,nil
}

func validateBoundaryRaw(raw []byte, claimWorlds map[string]bool)(Boundary,error){
	var b Boundary;_,err:=decodeExact(raw,[]string{"worlds","slots","gas"},"artifact.boundary",&b);if err!=nil{return b,err};if len(b.Worlds)==0{return b,reject("artifact.boundary.worlds: malformed")};seen:=map[string]bool{};for _,w:=range b.Worlds{if err:=ident("w",w,"artifact.boundary.world");err!=nil{return b,err};if seen[w]{return b,reject("artifact.boundary.worlds: malformed")};seen[w]=true};if len(seen)!=len(claimWorlds){return b,reject("artifact.boundary.worlds: claim world domain mismatch")};for w:=range claimWorlds{if !seen[w]{return b,reject("artifact.boundary.worlds: claim world domain mismatch")}}
	if b.Slots==nil{b.Slots=map[string][]string{}};for name,values:=range b.Slots{if name=="@world"||!tokenRE.MatchString(name){return b,reject("artifact.boundary.slot name: malformed")};if len(values)==0{return b,reject("artifact.boundary.slot domain: malformed")};vs:=map[string]bool{};for _,v:=range values{if !tokenRE.MatchString(v){return b,reject("artifact.boundary.slot value: malformed")};if vs[v]{return b,reject("artifact.boundary.slot domain: malformed")};vs[v]=true}}
	if b.Gas<1||b.Gas>maxGas{return b,reject("artifact.boundary.gas: malformed")};return b,nil
}

func consequence(payload []byte) string { h:=sha256.New();h.Write([]byte("RISU-K1-CAPSULE-CONSEQUENCE-V1\x00"));h.Write(payload);return "c:sha256:"+hex.EncodeToString(h.Sum(nil)) }
func execute(ins []Instr,labels map[string]int,point map[string]string,gas int)([]string,error){pc:=0;effects:=[]string{};for{if gas==0{return nil,reject("capsule closure incomplete: gas exhausted")};if pc<0||pc>=len(ins){return nil,reject("capsule closure incomplete: fell off program")};gas--;in:=ins[pc];switch in.Op{case "LABEL":pc++;case "IF_EQ":v,ok:=point[in.A];if !ok{return nil,reject("capsule closure incomplete: undeclared or missing input:"+in.A)};if v==in.B{pc=labels[in.C]}else{pc++};case "GOTO":pc=labels[in.A];case "EMIT_HEX":effects=append(effects,consequence(in.Payload));pc++;case "HALT":if len(effects)==0{return nil,reject("capsule closure incomplete: zero-effect halt")};return effects,nil;default:return nil,reject("capsule program: impossible opcode")}}}

func enumeratePoints(b Boundary, fn func(map[string]string) error) error {
	worlds:=append([]string(nil),b.Worlds...);sort.Strings(worlds);names:=make([]string,0,len(b.Slots));for n:=range b.Slots{names=append(names,n)};sort.Strings(names);domains:=make([][]string,len(names));for i,n:=range names{domains[i]=append([]string(nil),b.Slots[n]...);sort.Strings(domains[i])}
	var walk func(int,map[string]string) error;walk=func(i int,p map[string]string)error{if i==len(names){for _,w:=range worlds{q:=map[string]string{"@world":w};for k,v:=range p{q[k]=v};if err:=fn(q);err!=nil{return err}};return nil};for _,v:=range domains[i]{p[names[i]]=v;if err:=walk(i+1,p);err!=nil{return err}};delete(p,names[i]);return nil};return walk(0,map[string]string{})
}
func derive(program []byte,b Boundary)([]Pair,error){ins,labels,err:=parseProgram(program);if err!=nil{return nil,err};set:=map[Pair]bool{};err=enumeratePoints(b,func(p map[string]string)error{effects,e:=execute(ins,labels,p,b.Gas);if e!=nil{return e};w:=p["@world"];for _,c:=range effects{set[Pair{w,c}]=true};return nil});if err!=nil{return nil,err};rows:=make([]Pair,0,len(set));for p:=range set{rows=append(rows,p)};for _,w:=range b.Worlds{found:=false;for _,p:=range rows{if p.W==w{found=true;break}};if !found{return nil,reject("capsule closure incomplete: world without consequence")}};return sortedPairs(rows),nil}

func targetID(programSHA string,b Boundary,realize []Pair) string {var out bytes.Buffer;out.Write([]byte("RISU-K1-TARGET-CAPSULE-V1\x00"));out.WriteByte('S');out.Write(net(capsuleSemantics));out.WriteByte('P');out.Write(net(programSHA));out.WriteByte('G');out.Write(net(strconv.Itoa(b.Gas)));ws:=append([]string(nil),b.Worlds...);sort.Strings(ws);out.WriteByte('W');out.Write(net(strconv.Itoa(len(ws))));for _,w:=range ws{out.WriteByte('w');out.Write(net(w))};names:=make([]string,0,len(b.Slots));for n:=range b.Slots{names=append(names,n)};sort.Strings(names);out.WriteByte('D');out.Write(net(strconv.Itoa(len(names))));for _,n:=range names{vs:=append([]string(nil),b.Slots[n]...);sort.Strings(vs);out.WriteByte('s');out.Write(net(n));out.Write(net(strconv.Itoa(len(vs))));for _,v:=range vs{out.WriteByte('v');out.Write(net(v))}};rows:=sortedPairs(realize);out.WriteByte('R');out.Write(net(strconv.Itoa(len(rows))));for _,p:=range rows{out.WriteByte('r');out.Write(net(p.W));out.Write(net(p.C))};h:=sha256.Sum256(out.Bytes());return "t:sha256:"+hex.EncodeToString(h[:])}

func checkArtifact(raw []byte,expected string,claim Claim,claimWorlds map[string]bool,program []byte)(Artifact,[]Pair,string,error){
	h:=sha256.Sum256(raw);actual:="p:sha256:"+hex.EncodeToString(h[:]);if actual!=expected{return Artifact{},nil,"",reject("proof artifact: byte digest mismatch")};var a Artifact;m,err:=decodeExact(raw,[]string{"proof_format","claim_id","capsule_semantics","program_sha256","boundary"},"capsule proof",&a);if err!=nil{return a,nil,"",err};if a.ProofFormat!=proofKind{return a,nil,"",unsupported("unsupported proof artifact format")};if a.CapsuleSemantics!=capsuleSemantics{return a,nil,"",unsupported("unsupported capsule semantics")};if a.ClaimID!=claim.ClaimID{return a,nil,"",reject("capsule proof: claim mismatch")};if !hex64RE.MatchString(a.ProgramSHA256){return a,nil,"",reject("capsule proof: malformed program digest")};ph:=sha256.Sum256(program);actualProgram:=hex.EncodeToString(ph[:]);if a.ProgramSHA256!=actualProgram{return a,nil,"",reject("capsule proof: program digest mismatch")};b,err:=validateBoundaryRaw(m["boundary"],claimWorlds);if err!=nil{return a,nil,"",err};a.Boundary=b;realize,err:=derive(program,b);if err!=nil{return a,nil,"",err};tid:=targetID(actualProgram,b,realize);return a,realize,tid,nil
}

func checkCertificate(claimRaw,certRaw,artifactRaw,program []byte)(Result,error){
	claim,allow,worlds,err:=checkClaim(claimRaw);if err!=nil{return nil,err};var c Certificate;top,err:=decodeExact(certRaw,[]string{"wire","kind","claim_id","target_id","realize","closure_proof","grounding_proofs","evidence_roots","certificate_id"},"certificate",&c);if err!=nil{return nil,err};if err:=validateCertNested(top);err!=nil{return nil,err};if c.Wire!="risu.k1.w0"||c.Kind!="preservation_certificate"||c.ClaimID!=claim.ClaimID{return nil,reject("certificate: wire/kind/claim mismatch")};if err:=ident("t",c.TargetID,"certificate.target_id");err!=nil{return nil,err};submitted,err:=parseRelation(c.Realize,"certificate.realize");if err!=nil{return nil,err};if len(submitted)==0{return nil,reject("certificate.realize: empty")};if c.ClosureProof.Kind!=proofKind{return nil,unsupported("unsupported closure proof kind")}
	ground:=map[Pair]ProofRef{};for _,g:=range c.GroundingProofs{p,err:=parsePair(g.Pair[:],"certificate.grounding_entry.pair");if err!=nil{return nil,err};if _,ok:=ground[p];ok{return nil,reject("certificate.grounding_proofs: duplicate pair")};ground[p]=g.Proof};roots:=map[string]bool{};for _,r:=range c.EvidenceRoots{if err:=ident("e",r,"certificate.evidence_root");err!=nil{return nil,err};if roots[r]{return nil,reject("certificate.evidence_roots: malformed")};roots[r]=true};if err:=ident("cert",c.CertificateID,"certificate.certificate_id");err!=nil{return nil,err};if c.CertificateID!=certificateID(c,submitted){return nil,reject("certificate.certificate_id: mismatch")}
	_,derived,tid,err:=checkArtifact(artifactRaw,c.ClosureProof.Artifact,claim,worlds,program);if err!=nil{return nil,err};if c.TargetID!=tid{return nil,reject("certificate: target commitment mismatch")};if !equalPairSets(submitted,derived){return nil,reject("certificate: submitted REALIZE is not exact derived capsule closure")};if len(ground)!=len(derived){return nil,reject("certificate: grounding set is not exactly derived REALIZE")};for _,p:=range derived{ref,ok:=ground[p];if !ok{return nil,reject("certificate: grounding set is not exactly derived REALIZE")};if ref.Kind!=proofKind||ref.Artifact!=c.ClosureProof.Artifact{return nil,reject("certificate: grounding proof does not bind exact capsule artifact")}}
	allowSet:=pairSet(allow);for _,p:=range derived{if !allowSet[p]{return nil,reject("certificate: forbidden derived consequence present")}}
	rows:=make([][]string,len(derived));for i,p:=range sortedPairs(derived){rows[i]=[]string{p.W,p.C}}
	return Result{"checker":"risu-k1-checker-w6","proof_status":"ACCEPTED","semantic_claim":"PRESERVATION","assurance_scope":"BOUNDED_HERMETIC_CAPSULE_EXHAUSTIVE","implementation_binding":true,"implementation_scope":"EXACT_CAPSULE_PROGRAM_AND_FINITE_BOUNDARY","claim_id":claim.ClaimID,"target_id":tid,"certificate_id":c.CertificateID,"world_count":len(worlds),"realize_pair_count":len(derived),"derived_realize":rows},nil
}

func read(path string)([]byte,error){b,err:=os.ReadFile(path);if err!=nil{return nil,reject("cannot read "+path+": "+err.Error())};return b,nil}
func main(){claimP:=flag.String("claim","","claim");certP:=flag.String("certificate","","certificate");artP:=flag.String("artifact","","artifact");progP:=flag.String("program","","program");flag.Parse();var result Result
	if *claimP==""||*certP==""||*artP==""||*progP==""{result=Result{"checker":"risu-k1-checker-w6","proof_status":"REJECTED","semantic_claim":"NONE","reason":"missing required argument"}}else{claimRaw,e1:=read(*claimP);certRaw,e2:=read(*certP);artRaw,e3:=read(*artP);progRaw,e4:=read(*progP);var err error;if e1!=nil{err=e1}else if e2!=nil{err=e2}else if e3!=nil{err=e3}else if e4!=nil{err=e4}else{result,err=checkCertificate(claimRaw,certRaw,artRaw,progRaw)};if err!=nil{switch err.(type){case unsupportedError:result=Result{"checker":"risu-k1-checker-w6","proof_status":"UNSUPPORTED","semantic_claim":"UNKNOWN","reason":err.Error()};default:result=Result{"checker":"risu-k1-checker-w6","proof_status":"REJECTED","semantic_claim":"NONE","reason":err.Error()}}}}
	enc:=json.NewEncoder(os.Stdout);enc.SetEscapeHTML(false);_ = enc.Encode(result)
}
