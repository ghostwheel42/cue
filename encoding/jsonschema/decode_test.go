// Copyright 2019 CUE Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jsonschema_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"golang.org/x/tools/txtar"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/errors"
	"cuelang.org/go/cue/format"
	"cuelang.org/go/cue/token"
	"cuelang.org/go/encoding/json"
	"cuelang.org/go/encoding/jsonschema"
	"cuelang.org/go/encoding/yaml"
	"cuelang.org/go/internal/astinternal"
	"cuelang.org/go/internal/cuetdtest"
	"cuelang.org/go/internal/cuetxtar"
	_ "cuelang.org/go/pkg"
)

// TestDecode reads the testdata/*.txtar files, converts the contained
// JSON schema to CUE and compares it against the output.
//
// Set CUE_UPDATE=1 to update test files with the corresponding output.
func TestDecode(t *testing.T) {
	test := cuetxtar.TxTarTest{
		Root:   "./testdata",
		Name:   "decode",
		Matrix: cuetdtest.FullMatrix,
	}
	test.Run(t, func(t *cuetxtar.Test) {
		cfg := &jsonschema.Config{}

		if t.HasTag("openapi") {
			cfg.Root = "#/components/schemas/"
			cfg.Map = func(p token.Pos, a []string) ([]ast.Label, error) {
				// Just for testing: does not validate the path.
				return []ast.Label{ast.NewIdent("#" + a[len(a)-1])}, nil
			}
		}
		cfg.Strict = t.HasTag("strict")

		ctx := t.CueContext()

		fsys, err := txtar.FS(t.Archive)
		if err != nil {
			t.Fatal(err)
		}
		v, err := readSchema(ctx, fsys)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Err(); err != nil {
			t.Fatal(err)
		}

		w := t.Writer("extract")
		expr, err := jsonschema.Extract(v, cfg)
		if err != nil {
			got := "ERROR:\n" + errors.Details(err, nil)
			w.Write([]byte(strings.TrimSpace(got) + "\n"))
			return
		}
		if expr == nil {
			t.Fatal("no expression was extracted")
		}

		b, err := format.Node(expr, format.Simplify())
		if err != nil {
			t.Fatal(errors.Details(err, nil))
		}
		b = append(bytes.TrimSpace(b), '\n')
		w.Write(b)
		if t.HasTag("noverify") {
			return
		}
		// Verify that the generated CUE compiles.
		schemav := ctx.CompileBytes(b, cue.Filename("generated.cue"))
		if err := schemav.Err(); err != nil {
			t.Fatal(errors.Details(err, nil))
		}
		testEntries, err := fs.ReadDir(fsys, "test")
		if err != nil {
			return
		}
		for _, e := range testEntries {
			file := path.Join("test", e.Name())
			var v cue.Value
			base := ""
			testData, err := fs.ReadFile(fsys, file)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case strings.HasSuffix(file, ".json"):
				expr, err := json.Extract(file, testData)
				if err != nil {
					t.Fatal(err)
				}
				v = ctx.BuildExpr(expr)
				base = strings.TrimSuffix(e.Name(), ".json")

			case strings.HasSuffix(file, ".yaml"):
				file, err := yaml.Extract(file, testData)
				if err != nil {
					t.Fatal(err)
				}
				v = ctx.BuildFile(file)
				base = strings.TrimSuffix(e.Name(), ".yaml")
			default:
				t.Fatalf("unknown file encoding for test file %v", file)
			}
			if err := v.Err(); err != nil {
				t.Fatalf("error building expression for test %v: %v", file, err)
			}
			rv := schemav.Unify(v)
			if strings.HasPrefix(e.Name(), "err-") {
				err := rv.Err()
				if err == nil {
					t.Fatalf("test %v unexpectedly passes", file)
				}
				if t.M.IsDefault() {
					// The error results of the different evaluators can vary,
					// so only test the exact results for the default evaluator.
					t.Writer(path.Join("testerr", base)).Write([]byte(errors.Details(err, nil)))
				}
			} else {
				if err := rv.Err(); err != nil {
					t.Fatalf("test %v unexpectedly fails", file)
				}
			}
		}
	})
}

func readSchema(ctx *cue.Context, fsys fs.FS) (cue.Value, error) {
	jsonData, jsonErr := fs.ReadFile(fsys, "schema.json")
	yamlData, yamlErr := fs.ReadFile(fsys, "schema.yaml")
	switch {
	case jsonErr == nil && yamlErr == nil:
		return cue.Value{}, fmt.Errorf("cannot define both schema.json and schema.yaml")
	case jsonErr == nil:
		expr, err := json.Extract("schema.json", jsonData)
		if err != nil {
			return cue.Value{}, err
		}
		return ctx.BuildExpr(expr), nil
	case yamlErr == nil:
		file, err := yaml.Extract("schema.yaml", yamlData)
		if err != nil {
			return cue.Value{}, err
		}
		return ctx.BuildFile(file), nil
	}
	return cue.Value{}, fmt.Errorf("no schema.yaml or schema.json file found for test")
}

func TestMapURL(t *testing.T) {
	v := cuecontext.New().CompileString(`
type: "object"
properties: x: $ref: "https://something.test/foo#/definitions/blah"
`)
	var calls []string
	expr, err := jsonschema.Extract(v, &jsonschema.Config{
		MapURL: func(u *url.URL) (string, error) {
			calls = append(calls, u.String())
			return "other.test/something:blah", nil
		},
	})
	qt.Assert(t, qt.IsNil(err))
	b, err := format.Node(expr, format.Simplify())
	if err != nil {
		t.Fatal(errors.Details(err, nil))
	}
	qt.Assert(t, qt.DeepEquals(calls, []string{"https://something.test/foo"}))
	qt.Assert(t, qt.Equals(string(b), `
import "other.test/something:blah"

x?: blah.#blah
...
`[1:]))
}

func TestMapURLErrors(t *testing.T) {
	v := cuecontext.New().CompileString(`
type: "object"
properties: {
	x: $ref: "https://something.test/foo#/definitions/x"
	y: $ref: "https://something.test/foo#/definitions/y"
}
`, cue.Filename("foo.cue"))
	_, err := jsonschema.Extract(v, &jsonschema.Config{
		MapURL: func(u *url.URL) (string, error) {
			return "", fmt.Errorf("some error")
		},
	})
	qt.Assert(t, qt.Equals(errors.Details(err, nil), `
cannot determine import path from URL "https://something.test/foo": some error:
    foo.cue:4:5
`[1:]))
}

func TestX(t *testing.T) {
	t.Skip()
	data := `
-- schema.json --
`

	a := txtar.Parse([]byte(data))

	ctx := cuecontext.New()
	var v cue.Value
	var err error
	for _, f := range a.Files {
		switch path.Ext(f.Name) {
		case ".json":
			expr, err := json.Extract(f.Name, f.Data)
			if err != nil {
				t.Fatal(err)
			}
			v = ctx.BuildExpr(expr)
		case ".yaml":
			file, err := yaml.Extract(f.Name, f.Data)
			if err != nil {
				t.Fatal(err)
			}
			v = ctx.BuildFile(file)
		}
	}

	cfg := &jsonschema.Config{ID: "test"}
	expr, err := jsonschema.Extract(v, cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Fatal(astinternal.DebugStr(expr))
}
