package cli_test

import (
	"testing"

	"github.com/sthuck/k8s-sniffer/pkg/cli"
)

func TestParsePodPatterns(t *testing.T) {
	got, err := cli.ParsePodPatterns([]string{"foo-.*", "bar,baz"})
	if err != nil {
		t.Fatalf("ParsePodPatterns: %v", err)
	}
	want := []string{"foo-.*", "bar", "baz"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
