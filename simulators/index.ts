// Stop Point 8 — partner simulators + failure-mode harness: public barrel.
//
// One import surface for the synthetic simulator layer: configuration
// records (behaviors), the simulator engine and the synthetic platform
// (built ON the shared Stop Point 7 SDK — never re-implementing a contract),
// the deterministic failure-mode catalog, the metadata-only evidence module,
// and the contract-test runner that drives every simulator × failure-mode
// combination. Everything is configuration-driven: injected clocks,
// synthetic sandbox secrets, scripted transports — no real network, no
// partner-specific logic, no payload content ever surfaced.

export * from './behaviors.ts';
export * from './partnerSimulator.ts';
export * from './syntheticPlatform.ts';
export * from './failureModes.ts';
export * from './evidence.ts';
export * from './contractRunner.ts';
