package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type output struct {
	Checker string `json:"checker"`; ProofStatus string `json:"proof_status"`; SemanticClaim string `json:"semantic_claim"`; AuthorityCreated bool `json:"authority_created"`
	C3SourceID string `json:"c3_source_id,omitempty"`; C3SemanticID string `json:"c3_semantic_id,omitempty"`; GraphID string `json:"graph_id,omitempty"`; TraceMapID string `json:"trace_map_id,omitempty"`
	BoundaryPointCount int `json:"boundary_point_count,omitempty"`; TracePayloadCount int `json:"trace_payload_count,omitempty"`; ProjectedRealize [][]string `json:"projected_realize,omitempty"`; ForbiddenProjectedPairs [][]string `json:"forbidden_projected_pairs,omitempty"`; K1SubsetAllowed bool `json:"k1_subset_allowed"`
	C2ProgramSHA256 string `json:"c2_program_sha256,omitempty"`; C2ProgramBytes int `json:"c2_program_bytes,omitempty"`; C2DerivedGas int `json:"c2_derived_gas,omitempty"`; C2ArtifactID string `json:"c2_artifact_id,omitempty"`; C2TargetID string `json:"c2_target_id,omitempty"`; DirectTraceMap []map[string]any `json:"direct_trace_map,omitempty"`; Reason string `json:"reason,omitempty"`
}
func checkW8(claimRaw,profileRaw []byte,outdir string)(output,error){
	c,e:=parseClaim(claimRaw);if e!=nil{return output{},e};m,e:=parseModel(profileRaw,c);if e!=nil{return output{},e};srcPre:=append([]byte("RISU-K1-C3-MFST-SOURCE-V1\x00"),profileRaw...);src:=digest("c3src:sha256:",srcPre);sem:=semanticID(m);rs,e:=executeMFST(m);if e!=nil{return output{},e};prog,e:=c2Program(m,rs.Traces);if e!=nil{return output{},e};rep,gas,e:=replayC2(prog,m);if e!=nil{return output{},e};if !tracesEqual(rs.Traces,rep){return output{},rejectf("W8 direct C3 versus W8 C2 replay mismatch")};araw,aid,e:=c2Artifact(m,c.ID,prog,gas);if e!=nil{return output{},e};ps:=programSHA(prog);target:=c2Target(ps,m,gas,rs.Relation)
	if outdir!=""{if e=os.MkdirAll(outdir,0o755);e!=nil{return output{},e};if e=os.WriteFile(filepath.Join(outdir,"c2_program.cap"),prog,0o644);e!=nil{return output{},e};if e=os.WriteFile(filepath.Join(outdir,"c2_artifact.json"),araw,0o644);e!=nil{return output{},e}}
	rr:=make([]pair,0,len(rs.Relation));for p:=range rs.Relation{rr=append(rr,p)};sort.Slice(rr,func(i,j int)bool{if rr[i].W==rr[j].W{return rr[i].C<rr[j].C};return rr[i].W<rr[j].W});projected:=make([][]string,0,len(rr));for _,p:=range rr{projected=append(projected,[]string{p.W,p.C})};ff:=[]pair{};for _,p:=range rr{if !c.Allow[p]{ff=append(ff,p)}};forbidden:=make([][]string,0,len(ff));for _,p:=range ff{forbidden=append(forbidden,[]string{p.W,p.C})};tm:=[]map[string]any{};count:=0;for _,te:=range rs.Traces{pp:=map[string]string{};for k,v:=range te.Point{pp[k]=v};pls:=append([]string{},te.Payloads...);count+=len(pls);tm=append(tm,map[string]any{"point":pp,"payloads":pls})}
	return output{Checker:"risu-k1-checker-w8",ProofStatus:"ACCEPTED",SemanticClaim:"CANDIDATE_REFINEMENT",AuthorityCreated:false,C3SourceID:src,C3SemanticID:sem,GraphID:rs.GraphID,TraceMapID:rs.TraceID,BoundaryPointCount:len(rs.Traces),TracePayloadCount:count,ProjectedRealize:projected,ForbiddenProjectedPairs:forbidden,K1SubsetAllowed:len(forbidden)==0,C2ProgramSHA256:ps,C2ProgramBytes:len(prog),C2DerivedGas:gas,C2ArtifactID:aid,C2TargetID:target,DirectTraceMap:tm},nil
}
func main(){claim:=flag.String("claim","","W0 claim JSON");profile:=flag.String("profile","","MFST profile JSON");outdir:=flag.String("out-dir","","optional exact C2 output directory");flag.Parse();if *claim==""||*profile==""{fmt.Fprintln(os.Stderr,"--claim and --profile required");os.Exit(2)};cr,e:=os.ReadFile(*claim);if e!=nil{emitFailure(e);return};pr,e:=os.ReadFile(*profile);if e!=nil{emitFailure(e);return};r,e:=checkW8(cr,pr,*outdir);if e!=nil{emitFailure(e);return};emit(r)}
func emitFailure(e error){switch e.(type){case unsupportedError:emit(output{Checker:"risu-k1-checker-w8",ProofStatus:"UNSUPPORTED",SemanticClaim:"UNKNOWN",AuthorityCreated:false,Reason:e.Error()});default:emit(output{Checker:"risu-k1-checker-w8",ProofStatus:"REJECTED",SemanticClaim:"NONE",AuthorityCreated:false,Reason:e.Error()})}}
func emit(v output){b,_:=json.Marshal(v);fmt.Println(string(b))}
