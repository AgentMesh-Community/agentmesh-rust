//! The §13.5 usage receipt, responder side: declared meter quantities a host
//! reports during a dispatch, attached to the terminal respond as
//! `payload.usage` — where the envelope signature already covers them, which
//! is the whole design ("a usage report is a signed receipt with no new
//! signature"). The platform lifts the entries into declared meter events at
//! delivery; the signature proves authorship, not truth.
//!
//! Quantity twin of the EXT-8 allowance ledger: the allowance meters what
//! usage COSTS the owner (and feeds `payload.cost`, §19.3); this ledger
//! records what was CONSUMED, in the responder's own named units
//! (`tokens_out`, `tool_calls`, …), and feeds `payload.usage`. Reported
//! separately because they answer different questions and only one of them
//! needs a cost model. Mirrors `sdk-typescript/src/internal/meter-usage.ts`;
//! shapes pinned by `conformance/metering.json`.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, MeshError, Result};

/// §13.5: the closed set of observed meter names. A DECLARED meter must not
/// collide with them — the class is a trust statement, and a collision would
/// launder a responder's claim as a platform observation.
pub const OBSERVED_METERS: [&str; 7] = [
    "requests",
    "responses",
    "events",
    "bytes_in",
    "bytes_out",
    "tasks_completed",
    "task_ms",
];

/// One receipt entry: `{ meter, quantity }`. `quantity` is `u64` — the type is
/// the non-negativity rule, and serde refuses floats on the way in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageEntry {
    pub meter: String,
    pub quantity: u64,
}

/// Validate one report. `INPUT_INVALID` on a malformed meter name — a
/// malformed report is a host programming error and must fail at the report
/// site, not surface as a quietly absent receipt three calls later.
/// (Quantity needs no check here: `u64` already is the rule.)
pub fn validate_meter_name(meter: &str) -> Result<()> {
    let ok_len = !meter.is_empty() && meter.len() <= 64;
    let ok_chars = meter
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !ok_len || !ok_chars {
        return Err(MeshError::code(
            ErrorCode::InputInvalid,
            format!("meter name must match [a-z0-9_]{{1,64}} (§13.5): {meter:?}"),
        ));
    }
    if OBSERVED_METERS.contains(&meter) {
        return Err(MeshError::code(
            ErrorCode::InputInvalid,
            format!(
                "'{meter}' is an OBSERVED meter (§13.5) — a responder declares its own meters \
                 (tokens_in, tokens_out, model_ms, tool_calls, …), never the platform's"
            ),
        ));
    }
    Ok(())
}

/// How many tasks' un-attached reports are held before the oldest is dropped.
/// A task whose terminal respond never happens must not leak its accumulator
/// forever; first-seen eviction, the same shape as every other bounded ledger
/// in this SDK.
const MAX_TASKS: usize = 1000;

/// Per-task accumulation of declared meter reports. `report` is ADDITIVE
/// within a task (two model calls both reporting `tokens_out` sum); `take`
/// returns the task's entries — sorted by meter name (BTreeMap order), so the
/// receipt's canonical bytes are deterministic for identical reports — and
/// forgets them: the terminal respond is the receipt, and a second terminal
/// respond must not double-report.
#[derive(Debug, Default)]
pub(crate) struct MeterLedger {
    tasks: HashMap<String, BTreeMap<String, u64>>,
    order: VecDeque<String>,
}

impl MeterLedger {
    pub fn report(&mut self, task_id: &str, meter: &str, quantity: u64) -> Result<()> {
        validate_meter_name(meter)?;
        if task_id.is_empty() {
            return Ok(());
        }
        if !self.tasks.contains_key(task_id) {
            self.tasks.insert(task_id.to_string(), BTreeMap::new());
            self.order.push_back(task_id.to_string());
            if self.order.len() > MAX_TASKS {
                if let Some(oldest) = self.order.pop_front() {
                    self.tasks.remove(&oldest);
                }
            }
        }
        let m = self.tasks.get_mut(task_id).expect("just inserted");
        let slot = m.entry(meter.to_string()).or_insert(0);
        *slot = slot.saturating_add(quantity);
        Ok(())
    }

    /// The task's receipt entries, or `None` when nothing was reported.
    /// Clears the task's accumulator — attach-once.
    pub fn take(&mut self, task_id: &str) -> Option<Vec<UsageEntry>> {
        let m = self.tasks.remove(task_id)?;
        if m.is_empty() {
            return None;
        }
        Some(
            m.into_iter()
                .map(|(meter, quantity)| UsageEntry { meter, quantity })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additive_sorted_attach_once() {
        let mut l = MeterLedger::default();
        l.report("t1", "tokens_out", 4000).unwrap();
        l.report("t1", "tool_calls", 3).unwrap();
        l.report("t1", "tokens_out", 210).unwrap();
        assert_eq!(
            l.take("t1").unwrap(),
            vec![
                UsageEntry { meter: "tokens_out".into(), quantity: 4210 },
                UsageEntry { meter: "tool_calls".into(), quantity: 3 },
            ]
        );
        assert!(l.take("t1").is_none());
    }

    #[test]
    fn refuses_observed_and_malformed_names() {
        for name in OBSERVED_METERS {
            assert!(validate_meter_name(name).is_err());
        }
        assert!(validate_meter_name("Tokens-Out").is_err());
        assert!(validate_meter_name("").is_err());
        assert!(validate_meter_name(&"a".repeat(65)).is_err());
        assert!(validate_meter_name("tokens_out").is_ok());
    }
}
