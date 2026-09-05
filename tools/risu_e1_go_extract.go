package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"unicode"
)

type InputFile struct {
	Path      string `json:"path"`
	SourceB64 string `json:"source_b64"`
}
type Input struct {
	Files []InputFile `json:"files"`
}
type Fact map[string]any
type FileResult struct {
	Path       string `json:"path"`
	Facts      []Fact `json:"facts"`
	ParseError any    `json:"parse_error"`
}
type Output struct {
	Files []FileResult `json:"files"`
}

var versionTokens = []string{"sha", "etag", "version", "revision", "generation", "resourceversion"}
var mutationTokens = []string{"update", "patch", "put", "write", "delete", "create", "apply", "commit", "save", "mutate", "set"}
var errorTokens = []string{"error", "err", "fail", "reject", "conflict", "stale", "mismatch", "abort"}

func compact(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
func containsAny(s string, toks []string) bool {
	c := compact(s)
	for _, t := range toks {
		if strings.Contains(c, t) {
			return true
		}
	}
	return false
}
func isVersionish(s string) bool { return containsAny(s, versionTokens) }

func exprNames(e ast.Expr) []string {
	set := map[string]bool{}
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			set[x.Name] = true
		case *ast.SelectorExpr:
			set[x.Sel.Name] = true
		}
		return true
	})
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func callName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		parts := []string{f.Sel.Name}
		cur := f.X
		for {
			s, ok := cur.(*ast.SelectorExpr)
			if !ok {
				break
			}
			parts = append([]string{s.Sel.Name}, parts...)
			cur = s.X
		}
		if id, ok := cur.(*ast.Ident); ok {
			parts = append([]string{id.Name}, parts...)
		}
		return strings.Join(parts, ".")
	default:
		return ""
	}
}
func posLine(fs *token.FileSet, p token.Pos) int {
	if !p.IsValid() {
		return 0
	}
	return fs.Position(p).Line
}
func litOnly(e ast.Expr) bool {
	switch e.(type) {
	case *ast.BasicLit:
		return true
	}
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if _, ok := n.(*ast.Ident); ok {
			found = true
		}
		return true
	})
	return !found
}
func callsAndFlags(n ast.Node) (calls []string, mutation bool, errish bool, hasReturn bool) {
	ast.Inspect(n, func(x ast.Node) bool {
		switch z := x.(type) {
		case *ast.CallExpr:
			name := callName(z)
			if name != "" {
				calls = append(calls, name)
				mutation = mutation || containsAny(name, mutationTokens)
				errish = errish || containsAny(name, errorTokens)
			}
		case *ast.ReturnStmt:
			hasReturn = true
			for _, e := range z.Results {
				for _, name := range exprNames(e) {
					errish = errish || containsAny(name, errorTokens)
				}
			}
		}
		return true
	})
	sort.Strings(calls)
	return
}
func walkFunc(fs *token.FileSet, fn *ast.FuncDecl) []Fact {
	scope := fn.Name.Name
	facts := []Fact{{"type": "FUNCTION_DEF", "scope": scope, "line": posLine(fs, fn.Pos()), "name": scope, "params": func() []string {
		out := []string{}
		if fn.Type.Params != nil {
			for _, f := range fn.Type.Params.List {
				for _, n := range f.Names {
					out = append(out, n.Name)
				}
			}
		}
		return out
	}()}}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			if isVersionish(x.Name) {
				facts = append(facts, Fact{"type": "VERSION_LIKE_COORDINATE", "scope": scope, "line": posLine(fs, x.Pos()), "names": []string{x.Name}})
			}
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				lhsNames := exprNames(lhs)
				var rhs ast.Expr
				if i < len(x.Rhs) {
					rhs = x.Rhs[i]
				} else if len(x.Rhs) > 0 {
					rhs = x.Rhs[len(x.Rhs)-1]
				}
				if rhs == nil {
					continue
				}
				rhsNames := exprNames(rhs)
				if len(lhsNames) > 0 && len(rhsNames) > 0 {
					facts = append(facts, Fact{"type": "ASSIGNMENT_FLOW", "scope": scope, "line": posLine(fs, x.Pos()), "from_names": rhsNames, "to_names": lhsNames})
				}
				if len(lhsNames) > 0 && litOnly(rhs) {
					facts = append(facts, Fact{"type": "OVERWRITE_LITERAL", "scope": scope, "line": posLine(fs, x.Pos()), "names": lhsNames})
				}
			}
		case *ast.BinaryExpr:
			switch x.Op {
			case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
				names := append(exprNames(x.X), exprNames(x.Y)...)
				sort.Strings(names)
				if len(names) > 0 {
					facts = append(facts, Fact{"type": "COMPARISON_GUARD", "scope": scope, "line": posLine(fs, x.Pos()), "names": names, "operator": x.Op.String()})
				}
			}
		case *ast.CallExpr:
			name := callName(x)
			if name != "" {
				argNames := [][]string{}
				flat := []string{}
				for _, a := range x.Args {
					ns := exprNames(a)
					argNames = append(argNames, ns)
					flat = append(flat, ns...)
				}
				sort.Strings(flat)
				facts = append(facts, Fact{"type": "CALL_EDGE", "scope": scope, "line": posLine(fs, x.Pos()), "callee": name, "names": flat, "arg_names": argNames})
				if containsAny(name, mutationTokens) {
					facts = append(facts, Fact{"type": "MUTATION_OR_EFFECT_CALL", "scope": scope, "line": posLine(fs, x.Pos()), "callee": name, "names": flat})
				}
			}
		case *ast.IfStmt:
			cond := exprNames(x.Cond)
			tc, tm, te, tr := callsAndFlags(x.Body)
			ec := []string{}
			em, ee, er := false, false, false
			if x.Else != nil {
				ec, em, ee, er = callsAndFlags(x.Else)
			}
			facts = append(facts, Fact{"type": "BRANCH_CONTEXT", "scope": scope, "line": posLine(fs, x.Pos()), "condition_names": cond,
				"then_calls": tc, "then_mutation": tm, "then_errorish": te, "then_return": tr,
				"else_calls": ec, "else_mutation": em, "else_errorish": ee, "else_return": er})
		}
		return true
	})
	return facts
}
func main() {
	var in Input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out := Output{Files: []FileResult{}}
	for _, row := range in.Files {
		raw, err := base64.StdEncoding.DecodeString(row.SourceB64)
		if err != nil {
			out.Files = append(out.Files, FileResult{row.Path, []Fact{}, err.Error()})
			continue
		}
		fs := token.NewFileSet()
		file, perr := parser.ParseFile(fs, row.Path, raw, parser.AllErrors)
		if file == nil {
			out.Files = append(out.Files, FileResult{row.Path, []Fact{}, perr.Error()})
			continue
		}
		facts := []Fact{}
		for _, d := range file.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok {
				facts = append(facts, walkFunc(fs, fn)...)
			}
		}
		var pe any = nil
		if perr != nil {
			pe = perr.Error()
		}
		out.Files = append(out.Files, FileResult{row.Path, facts, pe})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
