//! Vouch renewal arithmetic (§4.4). Mirrors the TS SDK's `internal/vouch.ts`
//! and the vouch constants from its `constants.ts`.
//!
//! An agent exists on the mesh because a node vouched for it, and that vouch
//! carries an `expires_at` that the registry enforces at both ends of the
//! lifecycle: `handleRegister` refuses an expired attestation (§9.7) and the
//! reaper reclaims a registration whose attestation has lapsed. Registering
//! once and staying connected is therefore not enough to stay discoverable —
//! the vouch has to be re-minted while it is still valid.
//!
//! SPEC §9.2 names the legitimate path: "re-registration with a fresh vouch".
//! That is all a renewal is. The helpers here decide *when*.

use std::time::Duration;

use crate::inbound::parse_instant_ms;
use crate::manifest::AgentAttestation;

// ── the two numbers of the renewal loop ─────────────────────────────────────
//
// A node→agent vouch is a signed claim with an expiry, and the registry treats
// the expiry as real: the reaper reclaims a registration whose vouch has
// lapsed, and register itself refuses an expired one (§9.7). So the vouch is
// not a fact an agent establishes once at startup — it is a LEASE, and an
// agent that stays up longer than the lease has to renew it. That is what the
// renewal loop in `client.rs`/`node.rs` does; these are its numbers.

/// How long a minted node vouch is valid. Deliberately long: it is a lease on
/// a durable registration, not a session token. The lease being long is only
/// safe because something renews it — see [`VOUCH_RENEWAL_FRACTION`].
pub const DEFAULT_VOUCH_TTL_MS: i64 = 30 * 24 * 60 * 60_000;

/// The vouch an UNDECLARED registration gets (§9.2): ephemerality is the
/// default, durability is declared. An agent whose node profile states no
/// `availability_class` made no retention promise, so its lease is short —
/// generous for anything alive (renewal runs at two thirds of any TTL), and
/// self-cleaning for dev runs, crashed spawns, and one-shot scripts, which age
/// out in days instead of haunting discovery for a month. Declaring an
/// availability class is the one-field statement of intent that earns the full
/// lease above.
pub const EPHEMERAL_VOUCH_TTL_MS: i64 = 72 * 60 * 60_000;

/// How far into the vouch's life the SDK renews it. Two thirds: early enough
/// that a whole missed cycle (a suspended laptop, an unreachable registry, a
/// registry deploy) still leaves a third of the TTL to recover in, and late
/// enough that renewal is rare rather than chatty.
pub const VOUCH_RENEWAL_FRACTION: f64 = 2.0 / 3.0;

/// Ceiling on how often the renewal loop looks at the clock. The loop compares
/// wall-clock time against a stored deadline rather than sleeping until it, so
/// a host that suspends for a week renews on the first tick after it wakes
/// instead of waking a week late — which is the whole reason this is a
/// periodic check and not one long timer.
pub const MAX_VOUCH_CHECK_INTERVAL_MS: i64 = 60 * 60_000;

/// The instant (ms epoch) at which an attestation should be renewed: a fixed
/// fraction into its own lifetime. Derived from the attestation's own
/// `issued_at`/`expires_at` rather than from the configured TTL, so a vouch
/// minted with a different lifetime (a shorter operator policy, another SDK, a
/// hand-rolled attestation) still gets a proportionate renewal deadline.
///
/// `None` when the attestation carries no usable window — nothing to schedule
/// from, and inventing a deadline would be guessing.
///
/// Parity note: the TS `vouchRenewAt` returns a float; this returns whole
/// milliseconds (the fraction truncated), so the two may differ by under one
/// millisecond on windows not divisible by three. Nothing downstream can
/// observe that: the loop compares whole wall-clock milliseconds.
pub fn vouch_renew_at(att: &AgentAttestation) -> Option<i64> {
    let issued = parse_instant_ms(&att.issued_at)?;
    let expires = parse_instant_ms(&att.expires_at)?;
    if expires <= issued {
        return None;
    }
    Some(issued + ((expires - issued) as f64 * VOUCH_RENEWAL_FRACTION) as i64)
}

/// How often to check whether renewal is due, for a given vouch TTL.
///
/// Four checks inside the renewal window (the last third of the TTL): the
/// first one at or just after the deadline does the work, and the rest are the
/// retries a transient failure gets before the vouch actually lapses. Capped
/// so the 30-day default checks hourly instead of once every 30 hours — the
/// cap is what makes the loop robust to a host that suspends, since a tick
/// that arrives late still compares against the real clock and renews
/// immediately. Floor 1 ms, so a degenerate TTL never becomes a zero-delay
/// spin.
pub fn vouch_check_interval(ttl_ms: i64) -> Duration {
    let window = ttl_ms as f64 * (1.0 - VOUCH_RENEWAL_FRACTION);
    let ms = ((window / 4.0).floor() as i64).clamp(1, MAX_VOUCH_CHECK_INTERVAL_MS);
    Duration::from_millis(ms as u64)
}

/// When the current vouch expires, when it is next due for renewal, and why
/// the last renewal attempt failed (if it did) — the return of
/// [`AgentMesh::vouch`](crate::AgentMesh::vouch), mirroring the TS SDK's
/// `vouch` getter. `None` values mean "not registered". Exposed so a host that
/// attaches no security-warning sink can still see a lapsing vouch on its own
/// health surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VouchStatus {
    /// RFC 3339 expiry of the current vouch, from its attestation.
    pub expires_at: Option<String>,
    /// RFC 3339 instant the renewal loop will renew at (two thirds through the
    /// vouch's own window).
    pub renew_at: Option<String>,
    /// Why the last renewal attempt failed. Cleared by the next success.
    pub last_error: Option<String>,
}

/// Milliseconds-epoch → RFC 3339 UTC with millisecond precision and a `Z`
/// suffix — the shape `Date.toISOString()` produces, so [`VouchStatus`] reads
/// the same from both SDKs. `None` for an instant outside chrono's range.
pub(crate) fn ms_to_rfc3339(ms: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

/// "in 20d" / "in 3h" / "in 5m" / "already expired" / "expiry unknown" — the
/// human-scale time-left phrase the renewal-failure warning carries. Mirrors
/// the TS `humanizeLeft` (which feeds it `NaN` for an unknown expiry; here
/// that is `None`).
pub(crate) fn humanize_left(ms: Option<i64>) -> String {
    match ms {
        None => "expiry unknown".to_string(),
        Some(ms) if ms <= 0 => "already expired".to_string(),
        Some(ms) if ms >= 48 * 3_600_000 => {
            format!("in {}d", (ms as f64 / 86_400_000.0).round() as i64)
        }
        Some(ms) if ms >= 3_600_000 => format!("in {}h", (ms as f64 / 3_600_000.0).round() as i64),
        Some(ms) => format!("in {}m", ((ms as f64 / 60_000.0).round() as i64).max(1)),
    }
}

/// The §22.7 local signal a failed renewal raises: code
/// `vouch_renewal_failed`, subject = the agent, and a message naming the
/// cause, the expiry, the time left, and the consequence. Byte-for-byte the
/// message the TS SDK emits.
pub(crate) fn renewal_failed_warning(
    agent_id: &str,
    reason: &str,
    expires_at: Option<&str>,
    now_ms: i64,
) -> crate::inbound::SecurityWarning {
    let left_ms = expires_at.and_then(parse_instant_ms).map(|e| e - now_ms);
    let short_id: String = agent_id.chars().take(12).collect();
    crate::inbound::SecurityWarning {
        code: "vouch_renewal_failed".to_string(),
        message: format!(
            "could not renew the node vouch for agent {short_id}…: {reason}. The vouch expires \
             {expires} ({left}); after that the registry stops accepting this agent's \
             registration and drops it from discovery until it registers again. Retrying.",
            expires = expires_at.unwrap_or("at an unknown time"),
            left = humanize_left(left_ms),
        ),
        subject: Some(agent_id.to_string()),
        from: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn att(issued_at: &str, expires_at: &str) -> AgentAttestation {
        AgentAttestation {
            node: "NNODE".to_string(),
            agent: "UAGENT".to_string(),
            issued_at: issued_at.to_string(),
            expires_at: expires_at.to_string(),
            sig: String::new(),
        }
    }

    // Mirrors sdk-typescript __tests__/unit/vouch-renewal.test.ts,
    // "renewal arithmetic".

    #[test]
    fn renews_two_thirds_of_the_way_through_the_vouchs_own_lifetime() {
        let issued = parse_instant_ms("2026-07-25T00:00:00.000Z").unwrap();
        let ttl = 30 * 24 * 3_600_000i64;
        let at = vouch_renew_at(&att("2026-07-25T00:00:00.000Z", "2026-08-24T00:00:00.000Z"))
            .expect("usable window");
        // 20 days in, 10 days of runway left to retry in.
        assert_eq!(at - issued, 20 * 24 * 3_600_000);
        assert!(at < issued + ttl);
    }

    #[test]
    fn derives_the_deadline_from_the_attestation_not_the_configured_ttl() {
        // A vouch minted elsewhere (another SDK, a shorter operator policy)
        // still gets a proportionate deadline.
        let issued = parse_instant_ms("2026-07-25T00:00:00.000Z").unwrap();
        let at = vouch_renew_at(&att("2026-07-25T00:00:00.000Z", "2026-07-25T00:00:03.000Z"))
            .expect("usable window");
        assert_eq!(at, issued + 2_000);
    }

    #[test]
    fn has_no_deadline_for_an_unusable_window() {
        assert_eq!(vouch_renew_at(&att("", "")), None);
        assert_eq!(vouch_renew_at(&att("nonsense", "also nonsense")), None);
        // Already inverted: nothing sane to schedule.
        assert_eq!(
            vouch_renew_at(&att("2026-07-25T00:00:10Z", "2026-07-25T00:00:00Z")),
            None
        );
        // Zero-width: expires == issued is no window either.
        assert_eq!(
            vouch_renew_at(&att("2026-07-25T00:00:00Z", "2026-07-25T00:00:00Z")),
            None
        );
    }

    #[test]
    fn checks_hourly_for_the_30_day_default_and_proportionally_for_a_short_ttl() {
        assert_eq!(
            vouch_check_interval(DEFAULT_VOUCH_TTL_MS),
            Duration::from_millis(MAX_VOUCH_CHECK_INTERVAL_MS as u64)
        );
        // Four checks inside the last third of a 600ms vouch.
        assert_eq!(vouch_check_interval(600), Duration::from_millis(50));
        // Never a zero-delay spin.
        assert!(vouch_check_interval(1) > Duration::ZERO);
        assert!(vouch_check_interval(0) > Duration::ZERO);
    }

    #[test]
    fn the_ephemeral_lease_still_renews_well_inside_itself() {
        // 72h vouch: renewal due at 48h, 24h of runway; checks capped hourly.
        let at = vouch_renew_at(&att("2026-07-25T00:00:00Z", "2026-07-28T00:00:00Z")).unwrap();
        let issued = parse_instant_ms("2026-07-25T00:00:00Z").unwrap();
        assert_eq!(at - issued, 48 * 3_600_000);
        assert_eq!(
            vouch_check_interval(EPHEMERAL_VOUCH_TTL_MS),
            Duration::from_millis(MAX_VOUCH_CHECK_INTERVAL_MS as u64)
        );
    }

    #[test]
    fn humanize_left_speaks_in_the_largest_sensible_unit() {
        assert_eq!(humanize_left(None), "expiry unknown");
        assert_eq!(humanize_left(Some(0)), "already expired");
        assert_eq!(humanize_left(Some(-5_000)), "already expired");
        assert_eq!(humanize_left(Some(10 * 86_400_000)), "in 10d");
        assert_eq!(humanize_left(Some(3 * 3_600_000)), "in 3h");
        assert_eq!(humanize_left(Some(5 * 60_000)), "in 5m");
        assert_eq!(humanize_left(Some(1)), "in 1m"); // never "in 0m"
    }

    #[test]
    fn the_failure_warning_names_the_agent_the_cause_and_the_consequence() {
        let now = parse_instant_ms("2026-07-25T00:00:00Z").unwrap();
        let w = renewal_failed_warning(
            "UAGENT7SAMPLEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "connection refused",
            Some("2026-07-27T00:00:00.000Z"),
            now,
        );
        assert_eq!(w.code, "vouch_renewal_failed");
        assert_eq!(w.subject.as_deref(), Some("UAGENT7SAMPLEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(w.message.contains("UAGENT7SAMPL…"), "12-char id prefix: {}", w.message);
        assert!(w.message.contains("connection refused"));
        assert!(w.message.contains("expires 2026-07-27T00:00:00.000Z"));
        assert!(w.message.contains("(in 2d)"));
        assert!(w.message.contains("drops it from discovery"));
        assert!(w.message.ends_with("Retrying."));

        // No expiry recorded: the phrase degrades honestly.
        let unknown = renewal_failed_warning("UAGENT", "boom", None, now);
        assert!(unknown.message.contains("expires at an unknown time (expiry unknown)"));
    }
}
