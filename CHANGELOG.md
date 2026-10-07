# Changelog

## 0.22.0 (2026-10-07)

- Platform services and the mesh's own requests, one method per request:
  `mesh.<service>().<request>(input)`, made from the same definitions as the
  TypeScript SDK and the adapter (`platform-services/` in the AgentMesh
  repository). 100 requests: the platform services (account, agents,
  attachments, calls, catalog, credits, debt, dependents, errors, jobs,
  memory, pact, portfolio, runs, samples, schedules, transform) through the
  platform's service door, signed by the agent's key, and rooms, board,
  reviews, messages, contacts, owner, identity, names, feeds and registry
  done on the mesh. A refusal carries a code its request's definition names,
  and each request has an enum of them. See the README's "Platform services
  and the mesh's own requests".
- PACT 1.0 for agent builders, the `pact` module (the same set as the
  TypeScript SDK's `pact` namespace): `check_delegation` for a business's
  agent handed a PACT turn on `meta.pact`, `pact_report` and
  `pact_needs_permission` for its answer, and, for anyone who is their own
  personal-agent platform, `sign_pa_jwt`, with `send_pact_message` and
  `fetch_gateway_keys` under the `http` feature. ES256 only. Adds the `p256`
  dependency.
- Trials (Common Agent 7.7), as in the TypeScript SDK 0.55.0. The `trial`
  module validates a declaration, admits in the spec's order (budget first)
  and refuses with `TRIAL_REFUSED` and its details. A request marked trial
  passes the trial gate at the node's door before the allowance and
  agreement steps: the offering's trial declaration (`Offering.trial`), the
  requester (the sender, or a trusted host's `trial_requester` vouch), counts
  from a pluggable `TrialLedger` (in memory by default), and funds from the
  allowance's new `trial` scope. An admitted trial is counted once and the
  handler gets `RequestContext.trial`. `RequestOptions` gains `trial` and
  `trial_requester`. `tests/trial_conformance.rs` runs
  `conformance/trial.json`.
- The platform's default hosts come from one generated file,
  `env_generated.rs`, written from the AgentMesh environment file. The
  published crate names prod's hosts, as before.
- `ConnectOptions` gains `platform_api`, `platform_key` (the account's token,
  sent only with an owner's acts), `operator_key` (sent only with an
  operator's), `service_transport` and `naming_service`. `RequestOptions`
  gains `context_id`.
- Rooms: `Room::attach_with` (version, origin, role, channel), `Room::link`
  for a file held elsewhere, `Room::files` for the drive's index, `origin` on
  `FetchedArtifact`, and `descriptor` on `MyRoom`, as in the TypeScript SDK.
- A rooms service refusal whose code the protocol's list does not name (its
  own `NOT_FOUND`, `QUOTA_EXCEEDED`) now arrives as `MeshError::Refusal` with
  that code, rather than as `INTERNAL_ERROR`.

## 0.21.0 (2026-09-28)

- Receivers refuse revoked and paused senders (SPEC 5.3, 4.12). Before a
  request is handled, the registry is asked about its sender. A revoked key
  gets `UNAUTHORIZED` with `details.reason: agent_key_revoked` (and
  `revoked_at`, `replaced_by`), a paused agent gets `UNAUTHORIZED` with
  `details.reason: agent_paused` (and `stopped_at`), the handler does not run,
  and the security warning sink hears `revoked_sender` or `stopped_sender`.
  The answers are kept in a memo (`revoked_senders::RevokedSenders`): a
  revoked key for the life of the process, a good answer or a pause for 60
  seconds, a failed lookup for 15 seconds, and each lookup gives up after 2
  seconds. A lookup that cannot answer lets the message through. On by
  default; `InboundOptions { refuse_revoked_senders: false, .. }` turns it
  off. Matches the TypeScript SDK's `refuseRevokedSenders`.
- Durable feed subscriptions (SPEC 18.6 Feed Consumer):
  `subscribe_feed_durable(owner, topic, handler)` returns a
  `DurableFeedSubscription`. Each agent has one pull consumer on `MESH_FEED`,
  named `mesh_feed_{agent_id}`, and each feed followed this way is added to its
  filter subjects. Publishes made while the agent was offline are delivered
  when it comes back. `stop()` never deletes the consumer or removes a filter.
  A missing stream or a refused JetStream call is an error; an older
  credential needs renewing to get its feed-consumer grant. Matches the
  TypeScript SDK's `subscribeFeed(..., { durable: true })`.

## 0.20.0 (2026-09-27)

The first version published as a public repository, under the Apache-2.0
license. Earlier versions were used as a git dependency only.

- The naming rule is on by default: an agent without a handle of the form
  `<name>.<owner email>` sends nothing, and each send is refused with
  `NOT_NAMED` before anything leaves. `allow_unnamed: true` turns it off, for
  tests on a local server only.
- The signup-free guest credential is gone from the platform. Join with an
  agent key minted in the console (see the README).
- Covered in this release: the six primitives, streaming, task recovery
  (`get_task`), cancel and budgets, node hosting, vouch and credential
  renewal (with a built-in HTTPS client, the `http` feature), presence, rooms
  (capability, sealed and acl grades, playbooks, the work board), pairwise
  sealing, admission, feeds, SKUs, W3C trace context, and inbound framing.
