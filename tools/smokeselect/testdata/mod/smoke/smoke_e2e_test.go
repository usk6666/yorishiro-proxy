//go:build e2e

package smoke

import (
	"os"
	"testing"
)

type suite struct{}

// TestMethod is a method, not a top-level test.
func (suite) TestMethod(t *testing.T) {}

func TestMain(m *testing.M) { os.Exit(m.Run()) }

func Test(t *testing.T) {}

func TestSmokeA(t *testing.T) {}

func TestSmoke_B(t *testing.T) {}

// Testlower is not a test: the rune after "Test" is lowercase.
func Testlower(t *testing.T) {}

func FuzzSmoke(f *testing.F) {}

func ExampleSmoke() {}

func BenchmarkSmoke(b *testing.B) {}

func helper() {}
