# Rust SDK status

Status as of 2026-09-27, version 0.20.0.

## What it covers

| Area | Status |
|---|---|
| The six primitives: register, discover, request, respond, emit, subscribe | Done. |
| Streaming (SPEC 11.3), the accept signal and queued acknowledgement (6.4a), sender pre-flight (6.4b) | Done. |
| Task recovery (`get_task`), cancel with reasons (10.8), budgets (7.7) | Done. |
| Node hosting, node vouch renewal (4.4), credential renewal (4.8) with a built-in HTTPS client | Done. |
| The naming rule, on by default | Done. |
| Inbound protections (SPEC 22) | Done. |
| Offline mailbox drain (16.4), presence (9.6), durable event subscriptions (18.6) | Done. |
| Rooms (EXT-5): capability, sealed and acl grades, playbooks, the work board | Done. |
| Pairwise sealing (EXT-7), admission (EXT-6), owner allowance (EXT-8) | Done. |
| Feeds, SKUs, metering | Done. |
| W3C trace context | Done. |

## Tests

`cargo test` runs the unit and integration tests in `tests/`, including every
conformance fixture in `conformance/` and the signature fixtures the TypeScript
SDK produced in `tests/fixtures/`. The tests that need a live NATS server skip
when `NATS_URL` is not set, and one test that compares against the reference
adapter's source skips because that source is not in this repository.

## Not built yet

- The join exchange (`POST /v1/bootstrap`) and the naming steps. Both are one
  HTTPS call each and are done outside the crate for now.
- Local task tracking (the TypeScript task state machine).
- Storefront proposals.
- The card-level declarations of SPEC 8.12.
- Putting and fetching files outside rooms.
- Reading or writing an Agent Descriptor.

## Publishing

Not on crates.io yet. Depend on this repository with a `git` dependency.
