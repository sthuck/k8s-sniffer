package cli_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
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

func TestCaptureTLSFlags(t *testing.T) {
	var got cli.CaptureOptions
	cmd := cli.NewCaptureCommand(context.Background(), "test", func(_ context.Context, opts cli.CaptureOptions) error {
		got = opts
		return nil
	})
	cmd.SetArgs([]string{
		"-n", "prod", "--pod", "api-.*",
		"--tls", "ebpf", "--tls-out", "tls.jsonl", "--keylog-file", "keys.log",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Spec.TLSMode != capture.TLSModeEBPF {
		t.Fatalf("TLSMode = %s, want ebpf", got.Spec.TLSMode)
	}
	if got.Sink.TLSOut != "tls.jsonl" || got.Sink.KeylogFile != "keys.log" {
		t.Fatalf("sink = %+v", got.Sink)
	}

	cmd = cli.NewCaptureCommand(context.Background(), "test", func(context.Context, cli.CaptureOptions) error {
		return nil
	})
	cmd.SetArgs([]string{"-n", "prod", "--pod", "api", "--tls", "mitm"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "unknown tls mode") {
		t.Fatalf("Execute error = %v, want unknown tls mode", err)
	}

	cmd = cli.NewCaptureCommand(context.Background(), "test", func(_ context.Context, opts cli.CaptureOptions) error {
		got = opts
		return nil
	})
	cmd.SetArgs([]string{"-n", "prod", "--pod", "api"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("default Execute: %v", err)
	}
	if got.Spec.TLSMode != capture.TLSModeAuto {
		t.Fatalf("default TLSMode = %s, want auto", got.Spec.TLSMode)
	}
}
