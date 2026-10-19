package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// hermeticGo isolates the real `go list` from the caller's environment so the
// testdata modules are listed exactly as checked in.
func hermeticGo(t *testing.T) {
	t.Helper()
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "off")
}

func testdataDir(t *testing.T, name string) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// selectMod runs Select against testdata/mod through the real `go list`.
func selectMod(t *testing.T) *Selection {
	t.Helper()
	hermeticGo(t)
	sel, err := Select(context.Background(), GoList, testdataDir(t, "mod"), DefaultTags, []string{"./..."})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	return sel
}

func TestSelect_SelectsPlainE2EPackage(t *testing.T) {
	sel := selectMod(t)
	got := sel.Tests["example.com/smk/smoke"]
	if !contains(got, "TestSmokeA") {
		t.Fatalf("smoke package tests = %v, want TestSmokeA", got)
	}
	re := sel.RunRegexp()
	if !strings.HasPrefix(re, "^(") || !strings.HasSuffix(re, ")$") {
		t.Fatalf("RunRegexp() = %q, want anchored ^(...)$", re)
	}
	m := regexp.MustCompile(re)
	if !m.MatchString("TestSmokeA") {
		t.Errorf("RunRegexp() = %q does not match TestSmokeA", re)
	}
	if m.MatchString("TestSmokeAB") || m.MatchString("XTestSmokeA") {
		t.Errorf("RunRegexp() = %q is not anchored", re)
	}
}

func TestSelect_ExcludesFullOnlyPackage(t *testing.T) {
	sel := selectMod(t)
	if _, ok := sel.Tests["example.com/smk/fullonly"]; ok {
		t.Fatalf("fullonly selected; its only e2e file is e2e && !e2e_smoke: %v", sel.Tests)
	}
	if contains(sel.Names(), "TestFullOnly") || contains(sel.Names(), "TestFullUnit") {
		t.Fatalf("names leak fullonly tests: %v", sel.Names())
	}
}

func TestSelect_HelperOnlySmokeFileDoesNotSelectPackage(t *testing.T) {
	sel := selectMod(t)
	if _, ok := sel.Tests["example.com/smk/helperonly"]; ok {
		t.Fatalf("helperonly selected although its smoke file declares no tests: %v", sel.Tests)
	}
}

func TestSelect_UntaggedTestsOfSelectedPackageNotSelected(t *testing.T) {
	sel := selectMod(t)
	if _, ok := sel.Tests["example.com/smk/smoke"]; !ok {
		t.Fatalf("smoke package not selected: %v", sel.Tests)
	}
	m := regexp.MustCompile(sel.RunRegexp())
	for _, n := range []string{"TestUnitOnly", "TestPlain", "TestHelperUnit"} {
		if m.MatchString(n) {
			t.Errorf("RunRegexp() %q matches untagged test %s", sel.RunRegexp(), n)
		}
	}
	if _, ok := sel.Tests["example.com/smk/plain"]; ok {
		t.Errorf("untagged-only package selected")
	}
}

func TestSelect_XTestSmokeFile(t *testing.T) {
	sel := selectMod(t)
	if got := sel.Tests["example.com/smk/smoke"]; !contains(got, "TestXSmoke") {
		t.Fatalf("smoke package tests = %v, want TestXSmoke from package smoke_test", got)
	}
}

func TestSelect_PackageThatExistsOnlyUnderTags(t *testing.T) {
	sel := selectMod(t)
	if got := sel.Tests["example.com/smk/tagonly"]; !reflect.DeepEqual(got, []string{"TestTagOnly"}) {
		t.Fatalf("tagonly tests = %v, want [TestTagOnly]", got)
	}
}

// The smoke recipe runs `go test -race`, which sets the `race` build tag. A
// `//go:build e2e && race` file is therefore part of the smoke tier and must
// be selected; listing without -race would silently drop it (USK-1058 class).
func TestSelect_RaceConstrainedSmokeFileSelected(t *testing.T) {
	sel := selectMod(t)
	if got := sel.Tests["example.com/smk/raceonly"]; !reflect.DeepEqual(got, []string{"TestRaceOnly"}) {
		t.Fatalf("raceonly tests = %v, want [TestRaceOnly]; all = %v", got, sel.Tests)
	}
}

func TestSelect_FullSelection(t *testing.T) {
	sel := selectMod(t)
	wantPkgs := []string{"example.com/smk/collide", "example.com/smk/raceonly", "example.com/smk/smoke", "example.com/smk/tagonly"}
	if got := sel.Packages(); !reflect.DeepEqual(got, wantPkgs) {
		t.Errorf("Packages() = %v, want %v", got, wantPkgs)
	}
	wantNames := []string{"ExampleSmoke", "FuzzSmoke", "Test", "TestCollideSmoke", "TestRaceOnly", "TestSmokeA", "TestSmoke_B", "TestTagOnly", "TestXSmoke"}
	if got := sel.Names(); !reflect.DeepEqual(got, wantNames) {
		t.Errorf("Names() = %v, want %v", got, wantNames)
	}
}

func TestSelect_CollisionWarns(t *testing.T) {
	sel := selectMod(t)
	var hit bool
	for _, w := range sel.Warnings {
		if strings.Contains(w, "TestSmokeA") && strings.Contains(w, "example.com/smk/collide") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("Warnings = %q, want a warning that TestSmokeA also names an untagged test in example.com/smk/collide", sel.Warnings)
	}
}

func TestSelect_GoListPackageErrorIsFatal(t *testing.T) {
	hermeticGo(t)
	_, err := Select(context.Background(), GoList, testdataDir(t, "broken"), DefaultTags, []string{"./..."})
	if err == nil || !strings.Contains(err.Error(), "example.com/broken/mixed") {
		t.Fatalf("Select err = %v, want an error naming example.com/broken/mixed", err)
	}
}

func TestSelect_ListerFailureIsFatal(t *testing.T) {
	boom := errors.New("boom")
	list := func(context.Context, string, []string, []string) ([]Package, error) { return nil, boom }
	_, err := Select(context.Background(), list, ".", DefaultTags, []string{"./..."})
	if !errors.Is(err, boom) {
		t.Fatalf("Select err = %v, want wrapping %v", err, boom)
	}
}

func TestSelect_StubbedPackageErrorIsFatal(t *testing.T) {
	list := func(_ context.Context, _ string, tags, _ []string) ([]Package, error) {
		if len(tags) == 0 {
			return []Package{{ImportPath: "x/webui", Error: &PackageError{Err: "pattern dist/*: no matching files found"}}}, nil
		}
		return []Package{{ImportPath: "x/webui"}}, nil
	}
	_, err := Select(context.Background(), list, ".", DefaultTags, []string{"./..."})
	if err == nil || !strings.Contains(err.Error(), "dist/*") {
		t.Fatalf("Select err = %v, want the go list package error surfaced", err)
	}
}

func TestSelect_BuildConstraintsExcludeIsNotFatal(t *testing.T) {
	dir := testdataDir(t, "mod")
	list := func(_ context.Context, _ string, tags, _ []string) ([]Package, error) {
		if len(tags) == 0 {
			return []Package{{ImportPath: "example.com/smk/tagonly", Dir: filepath.Join(dir, "tagonly"),
				Error: &PackageError{Err: "build constraints exclude all Go files in " + filepath.Join(dir, "tagonly")}}}, nil
		}
		return []Package{{ImportPath: "example.com/smk/tagonly", Dir: filepath.Join(dir, "tagonly"), TestGoFiles: []string{"tagonly_e2e_test.go"}}}, nil
	}
	sel, err := Select(context.Background(), list, dir, DefaultTags, []string{"./..."})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got := sel.Tests["example.com/smk/tagonly"]; !reflect.DeepEqual(got, []string{"TestTagOnly"}) {
		t.Fatalf("tagonly tests = %v, want [TestTagOnly]", got)
	}
}

func TestTestFuncNames(t *testing.T) {
	const src = `package p

import "testing"

type s struct{}

func (s) TestMethod(t *testing.T) {}
func TestMain(m *testing.M)       {}
func Test(t *testing.T)           {}
func TestUpper(t *testing.T)      {}
func Test_under(t *testing.T)     {}
func Test1(t *testing.T)          {}
func Testfoo(t *testing.T)        {}
func TestÜmlaut(t *testing.T)     {}
func Testé(t *testing.T)          {}
func FuzzX(f *testing.F)          {}
func Fuzzy(f *testing.F)          {}
func Example()                    {}
func ExampleS_m()                 {}
func Examplefoo()                 {}
func BenchmarkX(b *testing.B)     {}
func helper()                     {}
`
	got, err := testFuncNames("p_test.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Test", "TestUpper", "Test_under", "Test1", "TestÜmlaut", "FuzzX", "Example", "ExampleS_m"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("testFuncNames = %v, want %v", got, want)
	}
}

func TestTestFuncNames_ParseErrorIsReturned(t *testing.T) {
	if _, err := testFuncNames("bad_test.go", []byte("package p\nfunc (")); err == nil {
		t.Fatal("want a parse error")
	}
}

func TestRun_OutputIsDeterministic(t *testing.T) {
	hermeticGo(t)
	args := []string{"-C", testdataDir(t, "mod"), "./..."}
	var first string
	for i := 0; i < 3; i++ {
		var out, errb bytes.Buffer
		if code := run(context.Background(), args, GoList, &out, &errb); code != 0 {
			t.Fatalf("run exit %d, stderr: %s", code, errb.String())
		}
		if i == 0 {
			first = out.String()
			continue
		}
		if out.String() != first {
			t.Fatalf("output differs between runs:\n%s\n---\n%s", first, out.String())
		}
	}
	want := "^(ExampleSmoke|FuzzSmoke|Test|TestCollideSmoke|TestRaceOnly|TestSmokeA|TestSmoke_B|TestTagOnly|TestXSmoke)$\n" +
		"example.com/smk/collide\nexample.com/smk/raceonly\nexample.com/smk/smoke\nexample.com/smk/tagonly\n"
	if first != want {
		t.Fatalf("output =\n%s\nwant\n%s", first, want)
	}
}

func TestRun_CollisionWarningGoesToStderrWithoutFailing(t *testing.T) {
	hermeticGo(t)
	var out, errb bytes.Buffer
	code := run(context.Background(), []string{"-C", testdataDir(t, "mod")}, GoList, &out, &errb)
	if code != 0 {
		t.Fatalf("run exit %d, want 0; stderr: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "warning") || !strings.Contains(errb.String(), "TestSmokeA") {
		t.Fatalf("stderr = %q, want a collision warning for TestSmokeA", errb.String())
	}
	if strings.Contains(out.String(), "warning") {
		t.Fatalf("warning leaked to stdout: %q", out.String())
	}
}

func TestRun_ListMode(t *testing.T) {
	hermeticGo(t)
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"-C", testdataDir(t, "mod"), "-list"}, GoList, &out, &errb); code != 0 {
		t.Fatalf("run exit %d, stderr: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "example.com/smk/tagonly\tTestTagOnly\n") {
		t.Fatalf("list output = %q, want a tab-separated tagonly line", out.String())
	}
}

func TestRun_EmptySelectionFails(t *testing.T) {
	hermeticGo(t)
	var out, errb bytes.Buffer
	code := run(context.Background(), []string{"-C", testdataDir(t, "empty")}, GoList, &out, &errb)
	if code == 0 {
		t.Fatalf("run exit 0 on empty selection; stdout: %q", out.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty on failure", out.String())
	}
	if !strings.Contains(errb.String(), "no smoke tests") {
		t.Errorf("stderr = %q, want an explanation", errb.String())
	}
}

func TestRun_GoListErrorFails(t *testing.T) {
	hermeticGo(t)
	var out, errb bytes.Buffer
	code := run(context.Background(), []string{"-C", testdataDir(t, "broken")}, GoList, &out, &errb)
	if code == 0 {
		t.Fatalf("run exit 0 on go list package error; stdout: %q", out.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty on failure", out.String())
	}
	if !strings.Contains(errb.String(), "example.com/broken/mixed") {
		t.Errorf("stderr = %q, want the failing package named", errb.String())
	}
}

func TestRun_BadFlagFails(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"-nope"}, GoList, &out, &errb); code == 0 {
		t.Fatal("run exit 0 on unknown flag")
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
