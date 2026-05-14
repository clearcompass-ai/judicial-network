package verification

import (
	"testing"
)

func TestPolicyStageEnabledFromEnv(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"", false},
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{"yes", true},
		{"on", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"off", false},
		{"  true  ", true}, // trimmed
		{"maybe", false},   // unrecognized → safe default
		{"truee", false},   // typo → safe default
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			t.Setenv(envPolicyStageEnable, c.input)
			if got := policyStageEnabledFromEnv(); got != c.want {
				t.Errorf("input=%q got=%t want=%t", c.input, got, c.want)
			}
		})
	}
}

func TestPolicyStageEnabledFromEnv_Unset(t *testing.T) {
	// Explicit absence is the production default. Setenv-then-Unsetenv
	// is the documented way to assert "key absent" in t.Setenv-based
	// table tests, but Setenv("") covers the same path because
	// os.Getenv("X") returns "" for both.
	t.Setenv(envPolicyStageEnable, "")
	if got := policyStageEnabledFromEnv(); got {
		t.Error("default should be OFF when env unset")
	}
}
