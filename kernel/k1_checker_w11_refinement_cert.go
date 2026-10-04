package main

// Independent C3 C0 refinement-certificate checker W11.
// W11 creates no preservation authority. It independently parses the C3
// certificate and re-runs the frozen W7/W8 + qualified W5/W6 evidence chain.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

const (
	wire   = "risu.k1.c3.refinement-certificate/v1"
	kind   = "mediated_refinement_preservation"
	verify = "risu.k1.c3.refinement-verification/v1"
)

type certDoc struct {
	Wire               string     `json:"wire"`
	Kind               string     `json:"kind"`
	VerificationProfile string    `json:"verification_profile"`
	ClaimID            string     `json:"claim_id"`
	C3SourceID         string     `json:"c3_source_id"`
	C3SemanticID       string     `json:"c3_semantic_id"`
	ReachableGraphID   string     `json:"reachable_graph_id"`
	OrderedTraceMapID  string     `json:"ordered_trace_map_id"`
	C2ProgramSHA256    string     `json:"c2_program_sha256"`
	C2ArtifactID       string     `json:"c2_artifact_id"`
	C2TargetID         string     `json:"c2_target_id"`
	ProjectedRealize   [][]string `json:"projected_realize"`
	C2CertificateID    string     `json:"c2_certificate_id"`
	CertificateID      string     `json:"certificate_id"`
}

var pats = map[string]*regexp.Regexp{
	"claim": regexp.MustCompile(`^claim:sha256:[0-9a-f]{64}$`),
	"src": regexp.MustCompile(`^c3src:sha256:[0-9a-f]{64}$`),
	"sem": regexp.MustCompile(`^c3sem:sha256:[0-9a-f]{64}$`),
	"graph": regexp.MustCompile(`^c3graph:sha256:[0-9a-f]{64}$`),
	"trace": regexp.MustCompile(`^c3trace:sha256:[0-9a-f]{64}$`),
	"sha": regexp.MustCompile(`^[0-9a-f]{64}$`),
	"p": regexp.MustCompile(`^p:sha256:[0-9a-f]{64}$`),
	"t": regexp.MustCompile(`^t:sha256:[0-9a-f]{64}$`),
	"w": regexp.MustCompile(`^w:sha256:[0-9a-f]{64}$`),
	"c": regexp.MustCompile(`^c:sha256:[0-9a-f]{64}$`),
	"cert": regexp.MustCompile(`^cert:sha256:[0-9a-f]{64}$`),
	"c3cert": regexp.MustCompile(`^c3cert:sha256:[0-9a-f]{64}$`),
}

func net(s string) []byte {
	b := []byte(s)
	return []byte(strconv.Itoa(len(b)) + ":" + s + ",")
}
func writeTag(b *bytes.Buffer, tag byte, s string) { b.WriteByte(tag); b.Write(net(s)) }

func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var scan func() error
	scan = func() error {
		tok, err := dec.Token()
		if err != nil { return err }
		d, ok := tok.(json.Delim)
		if !ok { return nil }
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token(); if err != nil { return err }
				k, ok := kt.(string); if !ok { return errors.New("object key not string") }
				if seen[k] { return fmt.Errorf("duplicate JSON key:%s", k) }
				seen[k] = true
				if err := scan(); err != nil { return err }
			}
			end, err := dec.Token(); if err != nil { return err }
			if end != json.Delim('}') { return errors.New("object close") }
		case '[':
			for dec.More() { if err := scan(); err != nil { return err } }
			end, err := dec.Token(); if err != nil { return err }
			if end != json.Delim(']') { return errors.New("array close") }
		default:
			return errors.New("unexpected delimiter")
		}
		return nil
	}
	if err := scan(); err != nil { return err }
	if _, err := dec.Token(); err != io.EOF { 
		if err == nil { return errors.New("trailing JSON value") }
		return err
	}
	return nil
}

func parseCert(raw []byte) (certDoc,error) {
	var c certDoc
	if err := rejectDuplicateKeys(raw); err != nil { return c, err }
	dec := json.NewDecoder(bytes.NewReader(raw)); dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil { return c, err }
	var extra any
	if err := dec.Decode(&extra); err != io.EOF { return c, errors.New("trailing JSON") }
	if c.Wire!=wire || c.Kind!=kind || c.VerificationProfile!=verify { return c,errors.New("certificate wire/kind/version") }
	checks:=[]struct{v,k,n string}{
		{c.ClaimID,"claim","claim_id"},{c.C3SourceID,"src","c3_source_id"},{c.C3SemanticID,"sem","c3_semantic_id"},
		{c.ReachableGraphID,"graph","reachable_graph_id"},{c.OrderedTraceMapID,"trace","ordered_trace_map_id"},
		{c.C2ProgramSHA256,"sha","c2_program_sha256"},{c.C2ArtifactID,"p","c2_artifact_id"},
		{c.C2TargetID,"t","c2_target_id"},{c.C2CertificateID,"cert","c2_certificate_id"},{c.CertificateID,"c3cert","certificate_id"},
	}
	for _,x:=range checks { if !pats[x.k].MatchString(x.v) { return c,fmt.Errorf("malformed %s",x.n) } }
	if _,err:=normalizeRelation(c.ProjectedRealize);err!=nil{return c,err}
	return c,nil
}

func normalizeRelation(rows [][]string)([][]string,error){
	seen:=map[string]bool{}; out:=make([][]string,0,len(rows))
	for _,r:=range rows{
		if len(r)!=2 || !pats["w"].MatchString(r[0]) || !pats["c"].MatchString(r[1]) { return nil,errors.New("malformed projected_realize") }
		k:=r[0]+"\x00"+r[1]; if seen[k] { return nil,errors.New("duplicate projected_realize pair") };seen[k]=true
		out=append(out,[]string{r[0],r[1]})
	}
	sort.Slice(out,func(i,j int)bool{if out[i][0]==out[j][0]{return out[i][1]<out[j][1]};return out[i][0]<out[j][0]})
	return out,nil
}

func c3CertID(c certDoc)(string,error){
	rows,err:=normalizeRelation(c.ProjectedRealize);if err!=nil{return "",err}
	var b bytes.Buffer;b.WriteString("RISU-K1-C3-REFINEMENT-CERT-V1\x00")
	writeTag(&b,'V',c.VerificationProfile);writeTag(&b,'C',c.ClaimID);writeTag(&b,'S',c.C3SourceID)
	writeTag(&b,'M',c.C3SemanticID);writeTag(&b,'G',c.ReachableGraphID);writeTag(&b,'H',c.OrderedTraceMapID)
	writeTag(&b,'P',c.C2ProgramSHA256);writeTag(&b,'A',c.C2ArtifactID);writeTag(&b,'T',c.C2TargetID)
	writeTag(&b,'R',strconv.Itoa(len(rows)))
	for _,r:=range rows{b.WriteByte('r');b.Write(net(r[0]));b.Write(net(r[1]))}
	writeTag(&b,'D',c.C2CertificateID)
	h:=sha256.Sum256(b.Bytes());return "c3cert:sha256:"+hex.EncodeToString(h[:]),nil
}

func evidenceRoot(src,trace,prog,aid string)string{
	var b bytes.Buffer;b.WriteString("RISU-K1-C3-REFINEMENT-C2-EVIDENCE-V1\x00")
	writeTag(&b,'S',src);writeTag(&b,'H',trace);writeTag(&b,'P',prog);writeTag(&b,'A',aid)
	h:=sha256.Sum256(b.Bytes());return "e:sha256:"+hex.EncodeToString(h[:])
}

func c2CertID(claimID,target,aid,root string, rows [][]string)(string,error){
	rs,err:=normalizeRelation(rows);if err!=nil{return "",err}
	var b bytes.Buffer;b.WriteString("RISU-K1-CERT-W0\x00");writeTag(&b,'C',claimID);writeTag(&b,'T',target)
	writeTag(&b,'R',strconv.Itoa(len(rs)));for _,r:=range rs{b.WriteByte('P');b.Write(net(r[0]));b.Write(net(r[1]))}
	b.WriteByte('Q');b.Write(net("k1.capsule-closure/v1"));b.Write(net(aid))
	writeTag(&b,'G',strconv.Itoa(len(rs)))
	for _,r:=range rs{b.WriteByte('g');b.Write(net(r[0]));b.Write(net(r[1]));b.Write(net("k1.capsule-closure/v1"));b.Write(net(aid))}
	writeTag(&b,'E',"1");b.WriteByte('V');b.Write(net(root))
	h:=sha256.Sum256(b.Bytes());return "cert:sha256:"+hex.EncodeToString(h[:]),nil
}

func makeC2Cert(claimID,src,trace,prog,aid,target string,rows [][]string)(map[string]any,string,error){
	rs,err:=normalizeRelation(rows);if err!=nil{return nil,"",err}
	root:=evidenceRoot(src,trace,prog,aid);cid,err:=c2CertID(claimID,target,aid,root,rs);if err!=nil{return nil,"",err}
	proof:=map[string]any{"kind":"k1.capsule-closure/v1","artifact":aid}
	grounds:=make([]any,0,len(rs)); rr:=make([]any,0,len(rs))
	for _,r:=range rs{pair:=[]string{r[0],r[1]};rr=append(rr,pair);grounds=append(grounds,map[string]any{"pair":pair,"proof":proof})}
	d:=map[string]any{"wire":"risu.k1.w0","kind":"preservation_certificate","claim_id":claimID,"target_id":target,
		"realize":rr,"closure_proof":proof,"grounding_proofs":grounds,"evidence_roots":[]string{root},"certificate_id":cid}
	return d,cid,nil
}

func runJSON(name string,args ...string)(map[string]any,error){
	cmd:=exec.Command(name,args...);var stderr bytes.Buffer;cmd.Stderr=&stderr
	out,err:=cmd.Output();if err!=nil{return nil,fmt.Errorf("engine non-success %s: %v %s",name,err,stderr.String())}
	var m map[string]any;if err:=json.Unmarshal(out,&m);err!=nil{return nil,fmt.Errorf("engine invalid JSON: %w",err)};return m,nil
}
func jEqual(a,b any)bool{aa,_:=json.Marshal(a);bb,_:=json.Marshal(b);return bytes.Equal(aa,bb)}
func strv(m map[string]any,k string)(string,error){v,ok:=m[k].(string);if !ok{return "",fmt.Errorf("missing string %s",k)};return v,nil}
func boolv(m map[string]any,k string)(bool,error){v,ok:=m[k].(bool);if !ok{return false,fmt.Errorf("missing bool %s",k)};return v,nil}
func relAny(v any)([][]string,error){raw,err:=json.Marshal(v);if err!=nil{return nil,err};var r [][]string;if err:=json.Unmarshal(raw,&r);err!=nil{return nil,err};return normalizeRelation(r)}
func fileEq(a,b string)(bool,error){x,e:=os.ReadFile(a);if e!=nil{return false,e};y,e:=os.ReadFile(b);if e!=nil{return false,e};return bytes.Equal(x,y),nil}

func reject(reason string)map[string]any{return map[string]any{"checker":"risu-k1-c3-cert-w11","proof_status":"REJECTED","semantic_claim":"NONE","authority_created":false,"reason":reason}}

func main(){
	claim:=flag.String("claim","","claim");profile:=flag.String("profile","","profile");certPath:=flag.String("certificate","","certificate")
	program:=flag.String("program","","program");artifact:=flag.String("artifact","","artifact")
	w7:=flag.String("w7","","W7 path");w8:=flag.String("w8","","W8 binary");w5:=flag.String("w5","","W5 path");w6:=flag.String("w6","","W6 binary")
	flag.Parse()
	emit:=func(v map[string]any){b,_:=json.Marshal(v);fmt.Println(string(b))}
	if *claim==""||*profile==""||*certPath==""||*program==""||*artifact==""||*w7==""||*w8==""||*w5==""||*w6==""{emit(reject("missing argument"));return}
	raw,e:=os.ReadFile(*certPath);if e!=nil{emit(reject(e.Error()));return};c,e:=parseCert(raw);if e!=nil{emit(reject(e.Error()));return}
	claimRaw,e:=os.ReadFile(*claim);if e!=nil{emit(reject(e.Error()));return};var claimObj map[string]any
	if e=json.Unmarshal(claimRaw,&claimObj);e!=nil{emit(reject("claim JSON"));return};claimID,ok:=claimObj["claim_id"].(string);if !ok{emit(reject("claim_id"));return}
	td,e:=os.MkdirTemp("","risu-c3-cert-w11-");if e!=nil{emit(reject(e.Error()));return};defer os.RemoveAll(td)
	o7:=filepath.Join(td,"w7");o8:=filepath.Join(td,"w8")
	r7,e:=runJSON("python3",*w7,"--claim",*claim,"--profile",*profile,"--out-dir",o7);if e!=nil{emit(reject(e.Error()));return}
	r8,e:=runJSON(*w8,"--claim",*claim,"--profile",*profile,"--out-dir",o8);if e!=nil{emit(reject(e.Error()));return}
	if r7["proof_status"]!="ACCEPTED"||r8["proof_status"]!="ACCEPTED"{emit(reject("C3 evidence engine did not accept"));return}
	for _,k:=range []string{"c3_source_id","c3_semantic_id","graph_id","trace_map_id","direct_trace_map","projected_realize","c2_program_sha256","c2_derived_gas","c2_artifact_id","c2_target_id","k1_subset_allowed"}{
		if !jEqual(r7[k],r8[k]){emit(reject("W7/W8 disagreement:"+k));return}
	}
	allowed,e:=boolv(r7,"k1_subset_allowed");if e!=nil||!allowed{emit(reject("C3 projection not subset of ALLOW"));return}
	p7:=filepath.Join(o7,"c2_program.cap");p8:=filepath.Join(o8,"c2_program.cap");a7:=filepath.Join(o7,"c2_artifact.json");a8:=filepath.Join(o8,"c2_artifact.json")
	for _,pair:=range [][2]string{{p7,p8},{a7,a8},{p7,*program},{a7,*artifact}}{ok,e:=fileEq(pair[0],pair[1]);if e!=nil||!ok{emit(reject("exact derived bytes mismatch"));return}}
	pbytes,_:=os.ReadFile(*program);ph:=sha256.Sum256(pbytes);ps:=hex.EncodeToString(ph[:]);rprog,_:=strv(r7,"c2_program_sha256");if ps!=rprog{emit(reject("program digest mismatch"));return}
	abytes,_:=os.ReadFile(*artifact);ah:=sha256.Sum256(abytes);aid:="p:sha256:"+hex.EncodeToString(ah[:]);raid,_:=strv(r7,"c2_artifact_id");if aid!=raid{emit(reject("artifact digest mismatch"));return}
	src,_:=strv(r7,"c3_source_id");trace,_:=strv(r7,"trace_map_id");target,_:=strv(r7,"c2_target_id");sem,_:=strv(r7,"c3_semantic_id");graph,_:=strv(r7,"graph_id")
	rows,e:=relAny(r7["projected_realize"]);if e!=nil{emit(reject("derived relation"));return}
	c2,c2id,e:=makeC2Cert(claimID,src,trace,rprog,aid,target,rows);if e!=nil{emit(reject(e.Error()));return}
	c2raw,_:=json.Marshal(c2);c2path:=filepath.Join(td,"c2-cert.json");if e=os.WriteFile(c2path,c2raw,0644);e!=nil{emit(reject(e.Error()));return}
	r5,e:=runJSON("python3",*w5,"--claim",*claim,"--certificate",c2path,"--artifact",*artifact,"--program",*program);if e!=nil{emit(reject(e.Error()));return}
	r6,e:=runJSON(*w6,"--claim",*claim,"--certificate",c2path,"--artifact",*artifact,"--program",*program);if e!=nil{emit(reject(e.Error()));return}
	for tag,r:=range map[string]map[string]any{"W5":r5,"W6":r6}{
		if r["proof_status"]!="ACCEPTED"||r["semantic_claim"]!="PRESERVATION"{emit(reject(tag+" downstream did not accept"));return}
		dr,e:=relAny(r["derived_realize"]);if e!=nil||!jEqual(dr,rows){emit(reject(tag+" downstream REALIZE mismatch"));return}
		if r["target_id"]!=target||r["certificate_id"]!=c2id{emit(reject(tag+" downstream commitment mismatch"));return}
	}
	expected:=certDoc{Wire:wire,Kind:kind,VerificationProfile:verify,ClaimID:claimID,C3SourceID:src,C3SemanticID:sem,
		ReachableGraphID:graph,OrderedTraceMapID:trace,C2ProgramSHA256:rprog,C2ArtifactID:aid,C2TargetID:target,
		ProjectedRealize:rows,C2CertificateID:c2id,CertificateID:c.CertificateID}
	if c.Wire!=expected.Wire||c.Kind!=expected.Kind||c.VerificationProfile!=expected.VerificationProfile||c.ClaimID!=expected.ClaimID||
		c.C3SourceID!=expected.C3SourceID||c.C3SemanticID!=expected.C3SemanticID||c.ReachableGraphID!=expected.ReachableGraphID||
		c.OrderedTraceMapID!=expected.OrderedTraceMapID||c.C2ProgramSHA256!=expected.C2ProgramSHA256||c.C2ArtifactID!=expected.C2ArtifactID||
		c.C2TargetID!=expected.C2TargetID||c.C2CertificateID!=expected.C2CertificateID||!jEqual(mustRel(c.ProjectedRealize),rows){
		emit(reject("transported field mismatch"));return
	}
	cid,e:=c3CertID(c);if e!=nil||cid!=c.CertificateID{emit(reject("C3 certificate_id mismatch"));return}
	emit(map[string]any{"checker":"risu-k1-c3-cert-w11","proof_status":"ACCEPTED","semantic_claim":"CANDIDATE_REFINEMENT_CERTIFICATE",
		"authority_created":false,"certificate_id":cid,"c2_certificate_id":c2id,"c3_source_id":src,
		"ordered_trace_map_id":trace,"c2_target_id":target,"realize_pair_count":len(rows)})
}
func mustRel(r [][]string)[][]string{x,e:=normalizeRelation(r);if e!=nil{return nil};return x}
