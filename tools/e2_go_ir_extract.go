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
)

type InputFile struct {
	Path      string `json:"path"`
	SourceB64 string `json:"source_b64"`
}
type Input struct {
	Files []InputFile `json:"files"`
}
type Span struct {
	StartLine int `json:"start_line"`
	StartCol  int `json:"start_col"`
	EndLine   int `json:"end_line"`
	EndCol    int `json:"end_col"`
}
type Fact struct {
	Kind         string              `json:"kind"`
	Scope        string              `json:"scope"`
	Span         Span                `json:"span"`
	Name         string              `json:"name,omitempty"`
	Params       []string            `json:"params,omitempty"`
	LHS          []string            `json:"lhs,omitempty"`
	RHS          []string            `json:"rhs,omitempty"`
	ValueKind    string              `json:"value_kind,omitempty"`
	Container    string              `json:"container,omitempty"`
	Field        string              `json:"field,omitempty"`
	Callee       string              `json:"callee,omitempty"`
	Args         [][]string          `json:"args,omitempty"`
	Kwargs       map[string][]string `json:"kwargs,omitempty"`
	ResultLabels []string            `json:"result_labels,omitempty"`
	Operands     [][]string          `json:"operands,omitempty"`
	Operators    []string            `json:"operators,omitempty"`
	Condition    []string            `json:"condition,omitempty"`
	Values       []string            `json:"values,omitempty"`
}
type OutputFile struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Parser string `json:"parser"`
	Error  string `json:"error,omitempty"`
	Facts  []Fact `json:"facts"`
}
type Output struct {
	Files []OutputFile `json:"files"`
}

func span(fset *token.FileSet, n ast.Node) Span {
	s := fset.Position(n.Pos())
	e := fset.Position(n.End())
	return Span{StartLine: s.Line, StartCol: max(0, s.Column-1), EndLine: e.Line, EndCol: max(0, e.Column-1)}
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func exprName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		b := exprName(x.X)
		if b != "" {
			return b + "." + x.Sel.Name
		}
		return x.Sel.Name
	case *ast.IndexExpr:
		b := exprName(x.X)
		if b != "" {
			return b + "[]"
		}
	}
	return ""
}
func labels(n ast.Node) []string {
	m := map[string]bool{}
	ast.Inspect(n, func(x ast.Node) bool {
		if x == nil {
			return true
		}
		switch y := x.(type) {
		case *ast.SelectorExpr:
			if z := exprName(y); z != "" {
				m[z] = true
			}
			return false
		case *ast.Ident:
			if y.Name != "" && y.Name != "true" && y.Name != "false" && y.Name != "nil" {
				m[y.Name] = true
			}
		}
		return true
	})
	out := make([]string, 0, len(m))
	for x := range m {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}
func callName(c *ast.CallExpr) string { return exprName(c.Fun) }

type fnRange struct {
	start, end token.Pos
	name       string
}

func scopeFor(pos token.Pos, ranges []fnRange) string {
	best := "<module>"
	width := int(^uint(0) >> 1)
	for _, r := range ranges {
		if r.start <= pos && pos <= r.end {
			w := int(r.end - r.start)
			if w < width {
				best = r.name
				width = w
			}
		}
	}
	return best
}

func extract(path string, src []byte) OutputFile {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.AllErrors)
	if err != nil {
		return OutputFile{Path: path, Status: "MATERIAL_PARSE_FAILURE", Parser: "go/parser+go/ast", Error: err.Error(), Facts: []Fact{}}
	}
	ranges := []fnRange{}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok {
			ranges = append(ranges, fnRange{fn.Pos(), fn.End(), fn.Name.Name})
		}
	}
	facts := []Fact{}
	emit := func(n ast.Node, fact Fact) {
		fact.Scope = scopeFor(n.Pos(), ranges)
		fact.Span = span(fset, n)
		facts = append(facts, fact)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			return true
		}
		switch x := n.(type) {
		case *ast.FuncDecl:
			params := []string{}
			if x.Type.Params != nil {
				for _, fld := range x.Type.Params.List {
					for _, nm := range fld.Names {
						params = append(params, nm.Name)
					}
				}
			}
			facts = append(facts, Fact{Kind: "FUNCTION", Scope: "<module>", Span: span(fset, x), Name: x.Name.Name, Params: params})
		case *ast.AssignStmt:
			lhs := []string{}
			rhs := []string{}
			for _, e := range x.Lhs {
				lhs = append(lhs, labels(e)...)
			}
			for _, e := range x.Rhs {
				rhs = append(rhs, labels(e)...)
			}
			sort.Strings(lhs)
			sort.Strings(rhs)
			emit(x, Fact{Kind: "ASSIGN", LHS: uniq(lhs), RHS: uniq(rhs), ValueKind: "assignment"})
		case *ast.ValueSpec:
			lhs := []string{}
			rhs := []string{}
			for _, nm := range x.Names {
				lhs = append(lhs, nm.Name)
			}
			for _, e := range x.Values {
				rhs = append(rhs, labels(e)...)
			}
			if len(rhs) > 0 {
				emit(x, Fact{Kind: "ASSIGN", LHS: uniq(lhs), RHS: uniq(rhs), ValueKind: "value_spec"})
			}
		case *ast.CallExpr:
			args := [][]string{}
			for _, a := range x.Args {
				args = append(args, labels(a))
			}
			emit(x, Fact{Kind: "CALL", Callee: callName(x), Args: args, Kwargs: map[string][]string{}, ResultLabels: []string{}})
		case *ast.BinaryExpr:
			op := x.Op.String()
			if op == "==" || op == "!=" || op == "<" || op == ">" || op == "<=" || op == ">=" {
				emit(x, Fact{Kind: "COMPARE", Operands: [][]string{labels(x.X), labels(x.Y)}, Operators: []string{op}})
			}
		case *ast.IfStmt:
			emit(x.Cond, Fact{Kind: "IF_GUARD", Condition: labels(x.Cond)})
		case *ast.ReturnStmt:
			vals := []string{}
			for _, e := range x.Results {
				vals = append(vals, labels(e)...)
			}
			emit(x, Fact{Kind: "RETURN", Values: uniq(vals)})
		case *ast.KeyValueExpr:
			key := exprName(x.Key)
			if key == "" {
				if id, ok := x.Key.(*ast.BasicLit); ok {
					key = strings.Trim(id.Value, "\"")
				}
			}
			if key != "" {
				emit(x, Fact{Kind: "FIELD_BIND", Container: "composite", Field: key, RHS: labels(x.Value)})
			}
		}
		return true
	})
	sort.SliceStable(facts, func(i, j int) bool {
		a, b := facts[i], facts[j]
		if a.Span.StartLine != b.Span.StartLine {
			return a.Span.StartLine < b.Span.StartLine
		}
		if a.Span.StartCol != b.Span.StartCol {
			return a.Span.StartCol < b.Span.StartCol
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		ai, _ := json.Marshal(a)
		bj, _ := json.Marshal(b)
		return string(ai) < string(bj)
	})
	return OutputFile{Path: path, Status: "PASS", Parser: "go/parser+go/ast", Facts: facts}
}
func uniq(xs []string) []string {
	m := map[string]bool{}
	for _, x := range xs {
		if x != "" {
			m[x] = true
		}
	}
	out := []string{}
	for x := range m {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}
func main() {
	var in Input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		panic(err)
	}
	out := Output{Files: []OutputFile{}}
	sort.Slice(in.Files, func(i, j int) bool { return in.Files[i].Path < in.Files[j].Path })
	for _, row := range in.Files {
		b, err := base64.StdEncoding.DecodeString(row.SourceB64)
		if err != nil {
			out.Files = append(out.Files, OutputFile{Path: row.Path, Status: "MATERIAL_PARSE_FAILURE", Parser: "go/parser+go/ast", Error: err.Error(), Facts: []Fact{}})
			continue
		}
		out.Files = append(out.Files, extract(row.Path, b))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
