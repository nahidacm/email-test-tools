package report

import "testing"

func TestTally(t *testing.T) {
	cases := []struct {
		step Step
		want Counts
	}{
		{Step{Status: Fail}, Counts{Fail: 1}},
		{Step{Status: Warn}, Counts{Warn: 1}},
		{Step{Status: OK}, Counts{OK: 1}},
		{Step{Status: Info}, Counts{}},
		{Step{Status: Skip}, Counts{}},
		// A blacklist-style step reports every list it checked.
		{Step{Status: Warn, Counts: &Counts{Warn: 1, OK: 20, Unchecked: 2}}, Counts{Warn: 1, OK: 20, Unchecked: 2}},
	}
	for _, c := range cases {
		if got := c.step.Tally(); got != c.want {
			t.Errorf("%+v: got %+v want %+v", c.step.Status, got, c.want)
		}
	}
}
