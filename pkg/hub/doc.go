// Package hub owns session lifecycle: pod discovery, node grouping, agent
// scheduling, stream fan-in and cleanup. It implements
// snifferv1.HubServiceServer and snifferv1.AgentIngestServiceServer so the same
// code serves the in-process CLI hub (Phase 1) and a standalone deployment
// (Phase 4).
//
// Placeholder: implementation lands with T1.4-T1.8.
package hub
