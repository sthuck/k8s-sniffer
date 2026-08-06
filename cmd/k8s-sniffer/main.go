package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sthuck/k8s-sniffer/pkg/cli"
	"github.com/sthuck/k8s-sniffer/pkg/log"
)

var version = "dev"

func main() {
	ctx := context.Background()
	root := &cobra.Command{
		Use:   "k8s-sniffer",
		Short: "Kubernetes multi-pod traffic sniffer",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			level, err := log.ResolveLevel(logLevelFlag(cmd), os.Getenv(log.EnvLevel))
			if err != nil {
				return fmt.Errorf("invalid --log-level: %w", err)
			}
			log.Init(log.Config{Level: level})
			return nil
		},
	}
	root.PersistentFlags().String("log-level", "", "Log verbosity: info (default) or debug")
	root.Version = version
	root.SetVersionTemplate("{{.Version}}\n")

	root.AddCommand(cli.NewCaptureCommand(ctx, version, cli.RunCapture))

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func logLevelFlag(cmd *cobra.Command) string {
	for cur := cmd; cur != nil; cur = cur.Parent() {
		if f := cur.PersistentFlags().Lookup("log-level"); f != nil {
			return f.Value.String()
		}
	}
	return ""
}
