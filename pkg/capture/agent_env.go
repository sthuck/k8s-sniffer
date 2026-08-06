package capture

const (
	EnvAgentSessionID = "K8S_SNIFFER_SESSION_ID"
	EnvAgentNode      = "K8S_SNIFFER_NODE"
	EnvAgentPod       = "K8S_SNIFFER_AGENT_POD"
	EnvAgentStreamID  = "K8S_SNIFFER_STREAM_ID"
	EnvAgentHubAddr   = "K8S_SNIFFER_HUB_ADDR"
	EnvAgentCRISocket = "K8S_SNIFFER_CRI_SOCKET"
	EnvAgentLogLevel  = "K8S_SNIFFER_LOG_LEVEL"

	AgentStreamMetadataKey = "x-k8s-sniffer-stream-id"
	AgentPodMetadataKey    = "x-k8s-sniffer-agent-pod"
)
