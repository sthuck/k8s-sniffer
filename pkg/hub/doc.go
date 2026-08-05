// Package hub owns session lifecycle: pod discovery, node grouping, agent
// scheduling, stream fan-in and cleanup. It implements
// snifferv1.HubServiceServer and snifferv1.AgentIngestServiceServer so the same
// code serves the in-process CLI hub (Phase 1) and a standalone deployment
// (Phase 4).
//
// Discovery and grouping live in pkg/hub/discovery (T1.4–T1.5); agent pod
// manifests and lifecycle in pkg/hub/agent (T1.6–T1.7); session orchestration
// in this package (T1.8).
package hub
