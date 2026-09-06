from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Sequence, Tuple

from .model import EDGE_KINDS, NODE_KINDS
from .overlay_common import OverlayGraph, _sha, _span_tuple, _contains, _same_span, _root_label, _slot_suffix, _specificity
from .overlay_control import CStmt, _control_functions, _smallest_stmt, _function_for_span
from .overlay_source import _augment_python_field_binds, _call_argument_index

OVERLAY_SCHEMA = "risu.e2-observability-overlay/v0.1"

def build_overlay(*, path: str, source: str, source_sha256: str, language: str,
                  facts: Sequence[Mapping[str,Any]], base_ir: Mapping[str,Any],
                  anchor_contract: Mapping[str,Any], anchor_contract_sha256: str) -> Dict[str,Any]:
    g=OverlayGraph(path,source_sha256)
    if language=="python":
        facts=_augment_python_field_binds(source,facts)
    functions_facts=[f for f in facts if f.get("kind")=="FUNCTION"]
    controls=_control_functions(source,language,functions_facts)
    function_nodes: Dict[str,str]={}
    param_nodes: Dict[str,List[str]]={}
    state_initial: Dict[str,Dict[str,set[str]]]={}
    return_ops: Dict[str,List[str]]={}
    call_rows: List[Dict[str,Any]]=[]
    rep_cache: Dict[Tuple[str,Tuple[int,int,int,int]],str]={}
    anchored_nodes: Dict[Tuple[str,str],str]={}
    anchor_by_span: Dict[Tuple[int,int,int,int],List[Tuple[str,Sequence[str]]]]={}
    for aname,a in anchor_contract["anchors"].items():
        anchor_by_span.setdefault(tuple(a["span"]),[]).append((aname,a["roles"]))

    for f in functions_facts:
        name=str(f["name"]); sp=_span_tuple(f)
        fn=g.node("OPERATION",f"function:{name}",sp,scope=name,operation_role="function_definition")
        g.evidenced(fn,sp,"function_definition")
        function_nodes[name]=fn; return_ops[name]=[]; state_initial[name]={}
        params=[]
        for idx,p in enumerate(f.get("params",[])):
            basis={"file_sha256":source_sha256,"scope":name,"coordinate":str(p),"definition_span":sp,"definition_role":"function_parameter","parameter_index":idx}
            did="def_"+_sha(basis)[:24]
            n=g.node("INPUT",str(p),sp,scope=name,role="value_instance",definition_role="function_parameter",definition_site_key=did,symbol_key=f"{path}::{name}::{p}",parameter_index=idx)
            g.evidenced(n,sp,"parameter_definition",parameter_index=idx)
            g.edge("BINDS_TO",n,fn,sp,binding="parameter",parameter_index=idx)
            params.append(n); state_initial[name].setdefault(str(p),set()).add(n)
        param_nodes[name]=params

    for aname,a in sorted(anchor_contract["anchors"].items()):
        sp=tuple(a["span"])
        evattrs={"anchor_name":aname,"anchor_contract_sha256":anchor_contract_sha256,"slice_sha256":a["slice_sha256"]}
        for role in a["roles"]:
            if role=="GUARD_COMPARISON": kind="GUARD"
            elif role=="EFFECT_BOUNDARY": kind="EFFECT"
            elif role in {"SUCCESS_OUTCOME","REJECTION_NO_EFFECT_OUTCOME"}: kind="OUTCOME"
            else: raise ValueError(f"unsupported anchor role:{role}")
            n=g.node(kind,f"anchor:{aname}:{role}",sp,anchor_name=aname,anchor_role=role,anchor_contract_sha256=anchor_contract_sha256,syntax_kind=a["syntax_kind"])
            g.evidenced(n,sp,"frozen_consequence_anchor",**evattrs)
            anchored_nodes[(aname,role)]=n

    facts_by_scope: Dict[str,List[Mapping[str,Any]]]={name:[] for name in controls}
    for f in facts:
        if f.get("kind")=="FUNCTION": continue
        sp=_span_tuple(f)
        scope=_function_for_span(controls,sp) or str(f.get("scope","<module>"))
        if scope in controls: facts_by_scope.setdefault(scope,[]).append(f)

    def projection_value(scope: str,label: str,span:Tuple[int,int,int,int],state:Mapping[str,set[str]]) -> List[str]:
        root=_root_label(label)
        bases=sorted(state.get(root,set()))
        if not bases: return []
        suffix=_slot_suffix(label)
        if not suffix: return bases
        out=[]
        for base in bases:
            basis={"file_sha256":source_sha256,"scope":scope,"read_label":label,"read_span":span,"base_definition":base,"role":"projection_read"}
            rid="read_"+_sha(basis)[:24]
            n=g.node("SEMANTIC_COORDINATE",label,span,scope=scope,role="projection_read",definition_site_key=rid,base_definition_id=base,projection_slot=suffix)
            g.evidenced(n,span,"projection_read")
            g.edge("DERIVES",base,n,span,derivation="field_or_member_projection",projection_slot=suffix)
            out.append(n)
        return out

    def resolve_group(scope:str, labels:Sequence[str], span:Tuple[int,int,int,int], state:Mapping[str,set[str]]) -> List[str]:
        candidates=[]
        for label in sorted(set(map(str,labels)),key=_specificity,reverse=True):
            vals=projection_value(scope,label,span,state)
            if vals:
                candidates.extend(vals)
                if _slot_suffix(label): break
        return sorted(set(candidates))

    def statement_facts(scope:str, stmt:CStmt, *, condition_only:bool=False) -> List[Mapping[str,Any]]:
        rows=[]
        target=stmt.condition_span if condition_only and stmt.condition_span else stmt.span
        for f in facts_by_scope.get(scope,[]):
            sp=_span_tuple(f)
            if not _contains(target,sp): continue
            if not condition_only:
                child=_smallest_stmt([stmt],sp)
                if child is not stmt: continue
            rows.append(f)
        return sorted(rows,key=lambda f:(_span_tuple(f),str(f.get("kind")),repr(sorted(f.items()))))

    call_by_fact_key: Dict[Tuple[str,Tuple[int,int,int,int],str],Dict[str,Any]]={}
    return_by_stmt: Dict[Tuple[str,Tuple[int,int,int,int]],str]={}
    compare_anchor_operands: Dict[str,Dict[int,List[str]]]={}
    definition_nodes: List[str]=[]
    representation_field_nodes: List[str]=[]

    def add_call(scope:str,f:Mapping[str,Any],state:Mapping[str,set[str]]) -> Dict[str,Any]:
        sp=_span_tuple(f); callee=str(f.get("callee") or "<dynamic>")
        op=g.node("OPERATION",f"call:{callee}",sp,scope=scope,operation_role="call",callee=callee)
        g.evidenced(op,sp,"call_expression")
        actuals=[]
        for idx,grp in enumerate(f.get("args",[])):
            vals=resolve_group(scope,grp,sp,state); actuals.append(vals)
            for src in vals: g.edge("CARRIES",src,op,sp,carrier_boundary="call_argument",argument_index=idx)
        for key,grp in sorted((f.get("kwargs") or {}).items()):
            vals=resolve_group(scope,grp,sp,state)
            for src in vals: g.edge("CARRIES",src,op,sp,carrier_boundary="keyword_argument",field=key)
        rbasis={"file_sha256":source_sha256,"scope":scope,"coordinate":f"call:{callee}","definition_span":sp,"definition_role":"call_result"}
        rid="def_"+_sha(rbasis)[:24]
        result=g.node("SEMANTIC_COORDINATE",f"call_result:{callee}",sp,scope=scope,role="value_instance",definition_role="call_result",definition_site_key=rid)
        g.evidenced(result,sp,"call_result_definition")
        g.edge("DERIVES",op,result,sp,derivation="call_result")
        definition_nodes.append(result)
        row={"scope":scope,"callee":callee,"span":sp,"op":op,"result":result,"actuals":actuals}
        call_rows.append(row); call_by_fact_key[(scope,sp,callee)]=row
        return row

    def add_rep_bind(scope:str,f:Mapping[str,Any],state:Mapping[str,set[str]],owner_span:Tuple[int,int,int,int]) -> str:
        sp=_span_tuple(f); key=(scope,owner_span)
        if key not in rep_cache:
            rep=g.node("OPERATION",f"representation:{scope}:{owner_span}",owner_span,scope=scope,operation_role="representation_instance",representation_instance_id="rep_"+_sha({"sha":source_sha256,"scope":scope,"owner_span":owner_span})[:24])
            g.evidenced(rep,owner_span,"representation_instance")
            rep_cache[key]=rep
        rep=rep_cache[key]; field=str(f.get("field","<field>"))
        basis={"file_sha256":source_sha256,"scope":scope,"coordinate_or_slot_identity":f"{rep}:{field}","definition_span":sp,"definition_role":"representation_field_write"}
        did="def_"+_sha(basis)[:24]
        fld=g.node("SEMANTIC_COORDINATE",field,sp,scope=scope,role="representation_field_value",definition_role="representation_field_write",definition_site_key=did,representation_instance_id=rep,field=field)
        g.evidenced(fld,sp,"representation_field_write")
        g.edge("BINDS_TO",fld,rep,sp,binding="representation_field",field=field)
        for src in resolve_group(scope,f.get("rhs",[]),sp,state): g.edge("DERIVES",src,fld,sp,derivation="representation_field_write",field=field)
        definition_nodes.append(fld); representation_field_nodes.append(fld)
        return rep

    def process_simple(scope:str,stmt:CStmt,state:MutableMapping[str,set[str]]) -> Tuple[MutableMapping[str,set[str]], bool]:
        rows=statement_facts(scope,stmt)
        calls=[]; reps=[]; compare_nodes=[]
        for f in rows:
            kind=f.get("kind"); sp=_span_tuple(f)
            if kind=="CALL": calls.append(add_call(scope,f,state))
            elif kind=="FIELD_BIND": reps.append(add_rep_bind(scope,f,state,stmt.span))
            elif kind=="COMPARE":
                anchor_match=next((an for an,a in anchor_contract["anchors"].items() if "GUARD_COMPARISON" in a["roles"] and _same_span(tuple(a["span"]),sp)),None)
                if anchor_match:
                    guard=anchored_nodes[(anchor_match,"GUARD_COMPARISON")]
                else:
                    guard=g.node("GUARD","comparison",sp,scope=scope,guard_role="comparison")
                    g.evidenced(guard,sp,"comparison_expression")
                operand_values={}
                for idx,grp in enumerate(f.get("operands",[])):
                    vals=resolve_group(scope,grp,sp,state); operand_values[idx]=vals
                    for src in vals: g.edge("COMPARES",src,guard,sp,operand_index=idx,operators=list(f.get("operators",[])))
                if anchor_match: compare_anchor_operands[anchor_match]=operand_values
                compare_nodes.append(guard)
            elif kind=="RETURN":
                op=g.node("OPERATION",f"return:{scope}",sp,scope=scope,operation_role="return_boundary")
                g.evidenced(op,sp,"return_statement")
                return_ops[scope].append(op); return_by_stmt[(scope,stmt.span)]=op
                for src in resolve_group(scope,f.get("values",[]),sp,state): g.edge("DERIVES",src,op,sp,derivation="return_value")
            elif kind=="IF_GUARD":
                pass
        if reps:
            outer_calls=[c for c in calls if all(not _contains(other["span"],c["span"]) or other is c for other in calls)]
            for rep in sorted(set(reps)):
                if outer_calls:
                    for c in outer_calls: g.edge("DERIVES",rep,c["result"],stmt.span,derivation="representation_to_call_result")
                if (scope,stmt.span) in return_by_stmt:
                    g.edge("DERIVES",rep,return_by_stmt[(scope,stmt.span)],stmt.span,derivation="representation_to_return")
        if (scope,stmt.span) in return_by_stmt and calls:
            outer=[c for c in calls if not any(c is not d and _contains(d["span"],c["span"]) for d in calls)]
            for c in outer: g.edge("DERIVES",c["result"],return_by_stmt[(scope,stmt.span)],stmt.span,derivation="call_result_to_return")
        if (scope,stmt.span) in return_by_stmt:
            for guard in sorted(set(compare_nodes)):
                g.edge("DERIVES",guard,return_by_stmt[(scope,stmt.span)],stmt.span,derivation="comparison_result_to_return")
        assigns=[f for f in rows if f.get("kind")=="ASSIGN"]
        for f in assigns:
            sp=_span_tuple(f)
            for label in f.get("lhs",[]):
                label=str(label)
                basis={"file_sha256":source_sha256,"scope":scope,"coordinate_or_slot_identity":label,"definition_span":sp,"definition_role":"assignment"}
                did="def_"+_sha(basis)[:24]
                n=g.node("SEMANTIC_COORDINATE",label,sp,scope=scope,role="value_instance",definition_role="assignment",definition_site_key=did,symbol_key=f"{path}::{scope}::{label}")
                g.evidenced(n,sp,"assignment_definition")
                for src in resolve_group(scope,f.get("rhs",[]),sp,state): g.edge("DERIVES",src,n,sp,derivation="assignment")
                contained=[c for c in calls if _contains(sp,c["span"])]
                outer=[c for c in contained if not any(c is not d and _contains(d["span"],c["span"]) for d in contained)]
                for c in outer: g.edge("DERIVES",c["result"],n,sp,derivation="call_result_to_assignment")
                state[label]={n}; definition_nodes.append(n)
        terminated = stmt.kind=="RETURN"
        return state, terminated

    control_node_for_stmt: Dict[Tuple[str,Tuple[int,int,int,int]],str]={}
    control_complete: List[Dict[str,Any]]=[]

    def first_control_target(scope:str,stmt:CStmt) -> str:
        key=(scope,stmt.span)
        if key in control_node_for_stmt: return control_node_for_stmt[key]
        matches=[]
        for aname,a in anchor_contract["anchors"].items():
            asp=tuple(a["span"])
            if _contains(stmt.span,asp): matches.append((aname,a))
        if stmt.kind=="RETURN":
            eff=next((anchored_nodes[(n,"EFFECT_BOUNDARY")] for n,a in matches if "EFFECT_BOUNDARY" in a["roles"]),None)
            rej=next((anchored_nodes[(n,"REJECTION_NO_EFFECT_OUTCOME")] for n,a in matches if "REJECTION_NO_EFFECT_OUTCOME" in a["roles"]),None)
            target=eff or rej or return_by_stmt.get((scope,stmt.span))
            if target is None:
                target=g.node("OPERATION",f"control_return:{scope}",stmt.span,scope=scope,operation_role="return_boundary")
                g.evidenced(target,stmt.span,"control_return")
            control_node_for_stmt[key]=target; return target
        if stmt.kind=="IF":
            anchored=None
            if stmt.condition_span:
                for aname,a in anchor_contract["anchors"].items():
                    asp=tuple(a["span"])
                    if "GUARD_COMPARISON" in a["roles"] and _contains(stmt.condition_span,asp):
                        anchored=anchored_nodes[(aname,"GUARD_COMPARISON")]; break
            target=anchored or g.node("GUARD",f"control_if:{scope}",stmt.condition_span or stmt.span,scope=scope,guard_role="control_condition")
            if anchored is None: g.evidenced(target,stmt.condition_span or stmt.span,"control_condition")
            control_node_for_stmt[key]=target; return target
        target=g.node("OPERATION",f"statement:{scope}",stmt.span,scope=scope,operation_role="statement")
        g.evidenced(target,stmt.span,"structured_statement")
        control_node_for_stmt[key]=target; return target

    def build_control_seq(scope:str,stmts:Sequence[CStmt],incoming:List[str],exit_node:str) -> List[str]:
        preds=list(incoming)
        for stmt in stmts:
            if stmt.kind=="IF":
                guard=first_control_target(scope,stmt)
                for p in preds: g.edge("PRECEDES",p,guard,stmt.condition_span or stmt.span,control_relation="structured_successor")
                tbranch=g.node("OPERATION",f"branch:true:{scope}",stmt.span,scope=scope,operation_role="branch_entry",branch_polarity=True)
                fbranch=g.node("OPERATION",f"branch:false:{scope}",stmt.span,scope=scope,operation_role="branch_entry",branch_polarity=False)
                g.evidenced(tbranch,stmt.span,"branch_entry"); g.evidenced(fbranch,stmt.span,"branch_entry")
                g.edge("GUARDS",guard,tbranch,stmt.condition_span or stmt.span,branch_polarity=True)
                g.edge("GUARDS",guard,fbranch,stmt.condition_span or stmt.span,branch_polarity=False)
                g.edge("PRECEDES",guard,tbranch,stmt.condition_span or stmt.span,branch_polarity=True)
                g.edge("PRECEDES",guard,fbranch,stmt.condition_span or stmt.span,branch_polarity=False)
                tout=build_control_seq(scope,stmt.then_body or [],[tbranch],exit_node)
                fout=build_control_seq(scope,stmt.else_body or [],[fbranch],exit_node)
                if tout and fout:
                    join=g.node("OPERATION",f"join:{scope}",stmt.span,scope=scope,operation_role="control_join")
                    g.evidenced(join,stmt.span,"control_join")
                    for p in sorted(set(tout+fout)): g.edge("PRECEDES",p,join,stmt.span,control_relation="join")
                    preds=[join]
                else:
                    preds=sorted(set(tout+fout))
                continue
            target=first_control_target(scope,stmt)
            for p in preds: g.edge("PRECEDES",p,target,stmt.span,control_relation="structured_successor")
            if stmt.kind=="RETURN":
                matches=[(n,a) for n,a in anchor_contract["anchors"].items() if _contains(stmt.span,tuple(a["span"]))]
                effrow=next(((n,a) for n,a in matches if "EFFECT_BOUNDARY" in a["roles"]),None)
                if effrow:
                    n,a=effrow; outn=anchored_nodes[(n,"SUCCESS_OUTCOME")]
                    g.edge("PRECEDES",target,outn,tuple(a["span"]),control_relation="effect_to_success_outcome")
                    g.edge("PRECEDES",outn,exit_node,tuple(a["span"]),control_relation="return_exit")
                else:
                    g.edge("PRECEDES",target,exit_node,stmt.span,control_relation="return_exit")
                preds=[]
            else:
                preds=[target]
        return preds

    def process_block_state(scope:str,stmts:Sequence[CStmt],state:MutableMapping[str,set[str]]) -> Tuple[List[MutableMapping[str,set[str]]], bool]:
        states=[{k:set(v) for k,v in state.items()}]
        for stmt in stmts:
            new_states=[]
            for st in states:
                if stmt.kind=="IF":
                    condition_calls=[]
                    for f in statement_facts(scope,stmt,condition_only=True):
                        kind=f.get("kind"); sp=_span_tuple(f)
                        if kind=="CALL": condition_calls.append(add_call(scope,f,st))
                        elif kind=="COMPARE":
                            anchor_match=next((an for an,a in anchor_contract["anchors"].items() if "GUARD_COMPARISON" in a["roles"] and _same_span(tuple(a["span"]),sp)),None)
                            guard=anchored_nodes[(anchor_match,"GUARD_COMPARISON")] if anchor_match else first_control_target(scope,stmt)
                            operand_values={}
                            for idx,grp in enumerate(f.get("operands",[])):
                                vals=resolve_group(scope,grp,sp,st); operand_values[idx]=vals
                                for src in vals: g.edge("COMPARES",src,guard,sp,operand_index=idx,operators=list(f.get("operators",[])))
                            if anchor_match: compare_anchor_operands[anchor_match]=operand_values
                        elif kind=="IF_GUARD":
                            guard=first_control_target(scope,stmt)
                            for src in resolve_group(scope,f.get("condition",[]),sp,st): g.edge("COMPARES",src,guard,sp,operand_index=-1,operators=["CONTROL_CONDITION"])
                    if condition_calls:
                        guard=first_control_target(scope,stmt)
                        outer=[c for c in condition_calls if not any(c is not d and _contains(d["span"],c["span"]) for d in condition_calls)]
                        for c in outer: g.edge("COMPARES",c["result"],guard,stmt.condition_span or stmt.span,operand_index=-1,operators=["CONTROL_PREDICATE_RESULT"])
                    tstates,_=process_block_state(scope,stmt.then_body or [],{k:set(v) for k,v in st.items()})
                    fstates,_=process_block_state(scope,stmt.else_body or [],{k:set(v) for k,v in st.items()})
                    new_states.extend(tstates); new_states.extend(fstates)
                else:
                    st2,terminated=process_simple(scope,stmt,{k:set(v) for k,v in st.items()})
                    if not terminated: new_states.append(st2)
            states=new_states
            if not states: return [], True
            if len(states)>1:
                merged: Dict[str,set[str]]={}
                for st in states:
                    for k,v in st.items(): merged.setdefault(k,set()).update(v)
                states=[merged]
        return states, False

    anchored_scopes=set()
    for aname,a in anchor_contract["anchors"].items():
        sc=_function_for_span(controls,tuple(a["span"]))
        if sc is None: raise ValueError(f"anchor outside function:{aname}")
        anchored_scopes.add(sc)
    for scope,row in sorted(controls.items()):
        state={k:set(v) for k,v in state_initial.get(scope,{}).items()}
        process_block_state(scope,row["stmts"],state)
        if scope in anchored_scopes:
            status="COMPLETE" if not row["unsupported"] else "INCOMPLETE_FOR_MUST_PATH"
            entry=g.node("OPERATION",f"entry:{scope}",tuple(row["span"]),scope=scope,operation_role="control_entry")
            exitn=g.node("OPERATION",f"exit:{scope}",tuple(row["span"]),scope=scope,operation_role="control_exit")
            g.evidenced(entry,tuple(row["span"]),"control_entry"); g.evidenced(exitn,tuple(row["span"]),"control_exit")
            outs=build_control_seq(scope,row["stmts"],[entry],exitn)
            for p in outs: g.edge("PRECEDES",p,exitn,tuple(row["span"]),control_relation="fallthrough_exit")
            control_complete.append({"scope":scope,"status":status,"unsupported":list(row["unsupported"]),"order_source":row["order_source"],"function_span":list(row["span"])})

    for inner in call_rows:
        containers=[outer for outer in call_rows if outer is not inner and outer["scope"]==inner["scope"] and _contains(outer["span"],inner["span"])]
        if not containers: continue
        outer=min(containers,key=lambda c:((c["span"][2]-c["span"][0])*100000+(c["span"][3]-c["span"][1]),c["span"]))
        idx=_call_argument_index(source,outer["span"],inner["span"])
        if idx is None: continue
        while len(outer["actuals"]) <= idx: outer["actuals"].append([])
        outer["actuals"][idx]=sorted(set(outer["actuals"][idx]+[inner["result"]]))
        g.edge("CARRIES",inner["result"],outer["op"],outer["span"],carrier_boundary="nested_call_result",argument_index=idx)

    for c in call_rows:
        simple=c["callee"].split(".")[-1]
        if simple not in function_nodes: continue
        g.edge("BINDS_TO",c["op"],function_nodes[simple],c["span"],binding="unique_acquired_function_definition",callee=simple)
        for idx,vals in enumerate(c["actuals"]):
            if idx >= len(param_nodes.get(simple,[])): break
            formal=param_nodes[simple][idx]
            for src in vals: g.edge("BINDS_TO",src,formal,c["span"],binding="call_argument_to_parameter",argument_index=idx,callee=simple)
        for ret in return_ops.get(simple,[]): g.edge("DERIVES",ret,c["result"],c["span"],derivation="function_return_to_call_result",callee=simple)

    binding_slots={}
    for slot_name,slot in sorted(anchor_contract.get("binding_slots",{}).items()):
        aname=str(slot["anchor"]); idx=int(slot["operand_index"])
        vals=compare_anchor_operands.get(aname,{}).get(idx,[])
        binding_slots[slot_name]={"anchor":aname,"operand_index":idx,"value_instance_ids":sorted(set(vals))}
        guard=anchored_nodes[(aname,"GUARD_COMPARISON")]
        for src in sorted(set(vals)): g.edge("BINDS_TO",src,guard,tuple(anchor_contract["anchors"][aname]["span"]),binding=slot_name,operand_index=idx,anchor_contract_sha256=anchor_contract_sha256)

    nodes=g.sorted_nodes(); edges=g.sorted_edges()
    doc={
        "schema":OVERLAY_SCHEMA,"semantic_authority":False,
        "base_ir_schema":base_ir.get("schema"),"base_ir_digest_sha256":base_ir.get("ir_digest_sha256"),
        "consequence_anchor_contract_sha256":anchor_contract_sha256,
        "files":list(base_ir.get("files",[])),
        "frontend_status":list(base_ir.get("frontend_status",[])),
        "control_completeness":sorted(control_complete,key=lambda x:x["scope"]),
        "definition_state_semantics":{"kill":"DEFINITE_WRITE_REPLACES_REACHING_SET_ON_SUCCESSOR_PATH","join":"EXPLICIT_UNION_NO_SYNTHETIC_VALUE","status":"COMPLETE_FOR_SUPPORTED_SEED_SUBSET"},
        "binding_slots":binding_slots,
        "nodes":nodes,"edges":edges,
        "implementation_claim_boundary":"D1_D2_D3_OBSERVABILITY_ONLY_NO_A3_A4_VERDICT",
    }
    validate_overlay(doc)
    doc["overlay_digest_sha256"]=_sha(doc)
    return doc


def validate_overlay(doc: Mapping[str,Any]) -> None:
    if doc.get("schema") != OVERLAY_SCHEMA: raise ValueError("overlay schema mismatch")
    if doc.get("semantic_authority") is not False: raise ValueError("semantic_authority must be false")
    nodes=list(doc.get("nodes",[])); edges=list(doc.get("edges",[])); ids={n["id"] for n in nodes}
    if len(ids)!=len(nodes): raise ValueError("duplicate overlay node id")
    eids={e["id"] for e in edges}
    if len(eids)!=len(edges): raise ValueError("duplicate overlay edge id")
    for n in nodes:
        if n["kind"] not in NODE_KINDS: raise ValueError(f"bad overlay node kind:{n['kind']}")
        if n["kind"]!="EVIDENCE" and not any(e["kind"]=="EVIDENCED_BY" and e["source"]==n["id"] for e in edges):
            raise ValueError(f"overlay node without evidence:{n['id']}")
    for e in edges:
        if e["kind"] not in EDGE_KINDS: raise ValueError(f"bad overlay edge kind:{e['kind']}")
        if e["source"] not in ids or e["target"] not in ids: raise ValueError(f"dangling overlay edge:{e['id']}")
    if not doc.get("base_ir_digest_sha256"): raise ValueError("base ir digest missing")
    if not doc.get("consequence_anchor_contract_sha256"): raise ValueError("anchor contract digest missing")
