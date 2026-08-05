// Package k8s wraps client construction so the hub (in-process today, in
// cluster after Phase 4) has one place that resolves credentials.
package k8s

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ClientConfig selects which cluster/credentials to use. Zero value means
// "in-cluster if possible, else the default kubeconfig chain".
type ClientConfig struct {
	// Kubeconfig is an explicit kubeconfig path (empty = default chain).
	Kubeconfig string
	// Context overrides the kubeconfig current-context.
	Context string
	// Namespace overrides the context's default namespace.
	Namespace string
	// UserAgent identifies the caller in apiserver audit logs.
	UserAgent string
}

// Client bundles a clientset with the namespace resolved from the kubeconfig,
// which the CLI uses when --namespace is omitted.
type Client struct {
	Clientset kubernetes.Interface
	// DefaultNamespace comes from the kubeconfig context, "default" in-cluster.
	DefaultNamespace string
	RestConfig       *rest.Config
}

// New builds a clientset. In-cluster config wins when the process runs in a
// pod and no explicit kubeconfig was given.
func New(cfg ClientConfig) (*Client, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cfg.Kubeconfig != "" {
		loadingRules.ExplicitPath = cfg.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if cfg.Context != "" {
		overrides.CurrentContext = cfg.Context
	}
	if cfg.Namespace != "" {
		overrides.Context.Namespace = cfg.Namespace
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)

	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("resolve kubernetes config: %w", err)
	}
	if cfg.UserAgent != "" {
		restConfig.UserAgent = cfg.UserAgent
	}

	namespace, _, err := clientConfig.Namespace()
	if err != nil {
		return nil, fmt.Errorf("resolve default namespace: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}

	return &Client{Clientset: clientset, DefaultNamespace: namespace, RestConfig: restConfig}, nil
}
