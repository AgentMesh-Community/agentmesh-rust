# Changelog

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
