# Changelog

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
