package assert

import (
	"strings"
	"testing"
)

func StringContains(t *testing.T, actual, expectedSubstring string) {
	t.Helper()

	if !strings.Contains(actual, expectedSubstring) {
		t.Errorf("got: %q; expected to contain: %q", actual, expectedSubstring)
	}
}

func Equal[T comparable](t *testing.T, actual, excepted T) {
	t.Helper()

	if actual != excepted {
		t.Errorf("got: %v, want: %v", actual, excepted)
	}
}

func NilError(t *testing.T, actual error) {
	t.Helper()

	if actual != nil {
		t.Errorf("got: %v; expected: nil", actual)
	}
}
