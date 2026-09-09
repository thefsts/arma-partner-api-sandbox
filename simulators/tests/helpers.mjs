// Stop Point 8 — simulators test fixtures.
//
// Synthetic sandbox material only: the shared scenario clock, the synthetic
// simulator identities + secrets, fixture scenario configs, and the
// engine-wiring helpers (fresh platform world + fresh simulator per test).
// No private partner identifiers, no real credentials — everything the
// harness drives is declared synthetic sandbox data (behaviors.ts).

import {
  makeScenarioClock,
  wellBehavedScenario,
  wellBehavedPartnerRecord,
  wellBehavedOrgRecord,
  SYNTHETIC_SIMULATOR_SECRETS,
  WELL_BEHAVED_SIMULATOR,
  ALTERNATE_ENTITLEMENT_SIMULATOR,
  ALTERNATE_CAPABILITY_SIMULATOR,
} from '../behaviors.ts';
import { PartnerSimulator } from '../partnerSimulator.ts';
import { SyntheticPlatform } from '../syntheticPlatform.ts';

export {
  makeScenarioClock,
  wellBehavedScenario,
  wellBehavedPartnerRecord,
  wellBehavedOrgRecord,
  SYNTHETIC_SIMULATOR_SECRETS,
  WELL_BEHAVED_SIMULATOR,
  ALTERNATE_ENTITLEMENT_SIMULATOR,
  ALTERNATE_CAPABILITY_SIMULATOR,
};

/**
 * A fresh wiring pair for one scenario: a synthetic platform with the
 * scenario's world assembled + a simulator configured for the scenario's
 * identity, both on the SAME injected deterministic clock.
 */
export function makeScenarioPair(scenario) {
  const clock = makeScenarioClock();
  const platform = new SyntheticPlatform({ scenario, clock: clock.now });
  platform.assembleWorld();
  const simulator = new PartnerSimulator({ identity: scenario.identity, clock: clock.now });
  return { clock, platform, simulator };
}

/**
 * Drive one scenario the way the contract runner does: present the request
 * plan `presentations` times under the SAME idempotency key, then open the
 * webhook phase at the genuinely accepted outcome.
 */
export function driveScenario(scenario) {
  const { platform, simulator } = makeScenarioPair(scenario);
  const presentations = Math.max(1, scenario.presentations ?? 1);
  const outcomes = [];
  for (let i = 0; i < presentations; i += 1) {
    outcomes.push(simulator.execute(scenario.request, scenario.partnerFaults, platform));
  }
  const accepted = outcomes.find((o) => o.processed.ok === true) ?? outcomes[outcomes.length - 1];
  const phase = platform.emitAndDeliver(accepted.requestId);
  return { platform, simulator, outcomes, phase };
}
