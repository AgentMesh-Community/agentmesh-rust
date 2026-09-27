//! §8.9 `sealing` — the one place the default is decided.
//!
//! ## Why this is not a boolean somebody flips
//!
//! Sealing has existed since 0.8.0 and nobody uses it, because the honest
//! default is cleartext and a default nobody changes is the real behaviour of
//! the system. The obvious fix is to turn sealing on globally. That fix breaks
//! the mesh: a sender that starts sealing to every agent holding an
//! `encryption_key` will send ciphertext to handlers that have never opened a
//! sealed payload, and the failure is silent at the sender and unreadable at
//! the receiver. Live agents, including a production fleet, are in exactly that
//! position — they publish a key so people can invite them to sealed rooms, and
//! their request handlers know nothing about it.
//!
//! So the switch is not global and it is not a boolean. It is a manifest field
//! an older implementation never writes, which makes the compatibility argument
//! structural rather than a promise: a manifest registered before this code
//! existed carries no `sealing`, senders read that as "has not said", and
//! absolutely nothing about that agent's traffic changes. An agent's posture
//! can only ever move when its own operator re-registers it.
//!
//! ## The rule
//!
//! The default is derived from what the agent ALREADY declared about the work
//! it does, so the vendor case is sealed without anybody remembering to ask:
//!
//! 1. An explicit choice from the operator wins, including [`SealingChoice::None`],
//!    which is how an agent that would otherwise qualify opts out.
//! 2. No encryption key, no posture. A posture is a promise about reading, and
//!    an agent with no key cannot keep it.
//! 3. An offering with a `credential` need (§8.5.1) earns `required`. That
//!    declaration means the agent will ask a caller to sign in to somebody's
//!    account at a third party, which is the one thing here that must not cross
//!    a broker in the clear.
//! 4. Otherwise `works_with` (§8.8) earns `preferred`. The agent moves a
//!    caller's material through a system it does not own, which is usually the
//!    caller's business data and sometimes a public weather feed — so it earns
//!    the posture that seals when both ends can and refuses nobody.
//! 5. Otherwise nothing.
//!
//! Kept byte-for-byte equivalent to the TypeScript
//! `internal/sealing-posture.ts`: a security default that differs between two
//! SDKs is two different defaults.

use crate::manifest::{Offering, WorksWith};

/// The posture values that travel on the wire (§8.9).
pub const SEALING_REQUIRED: &str = "required";
/// See [`SEALING_REQUIRED`].
pub const SEALING_PREFERRED: &str = "preferred";

/// What an operator may ask for at registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SealingChoice {
    /// Derive from what the agent declared (the default, and the point).
    #[default]
    Derive,
    /// Refuse a posture the derivation would otherwise apply.
    None,
    /// Ask callers to seal, and refuse a request that arrived in the clear.
    Required,
    /// Ask callers to seal; read cleartext anyway.
    Preferred,
}

/// Whether any offering declares a §8.5.1 `credential` need: the agent will ask
/// the caller to sign in to a named third-party service.
pub fn declares_credential_need(offerings: &[Offering]) -> bool {
    offerings.iter().any(|o| {
        o.needs.iter().flatten().any(|n| {
            n.credential
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
        })
    })
}

/// The §8.9 posture for a registration. `None` means "declare nothing", which
/// is the same thing every pre-existing manifest says.
pub fn derived_sealing(
    encryption_key: Option<&str>,
    works_with: Option<&[WorksWith]>,
    offerings: &[Offering],
    explicit: SealingChoice,
) -> Option<String> {
    match explicit {
        SealingChoice::None => return None,
        // Still gated on the key: declaring a posture an agent cannot honour
        // would make the registry refuse the whole registration (§8.9), which
        // is a confusing way to punish an operator for asking for the safer
        // thing.
        SealingChoice::Required => {
            return encryption_key.map(|_| SEALING_REQUIRED.to_string());
        }
        SealingChoice::Preferred => {
            return encryption_key.map(|_| SEALING_PREFERRED.to_string());
        }
        SealingChoice::Derive => {}
    }
    encryption_key?;
    if declares_credential_need(offerings) {
        return Some(SEALING_REQUIRED.to_string());
    }
    if works_with.is_some_and(|w| !w.is_empty()) {
        return Some(SEALING_PREFERRED.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{NeedEntry, Offering};

    fn offering_with_needs(needs: Vec<NeedEntry>) -> Offering {
        Offering {
            id: "file-a-claim".into(),
            name: "File a claim".into(),
            description: "File a claim on the caller's behalf".into(),
            tags: None,
            input_modes: None,
            output_modes: None,
            streaming: None,
            needs: Some(needs),
            delivers: None,
            reporting: None,
        }
    }

    fn offering_needing_credential() -> Offering {
        offering_with_needs(vec![NeedEntry {
            credential: Some("Colorado DMV".into()),
            ..Default::default()
        }])
    }

    const KEY: &str = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw";

    #[test]
    fn an_agent_that_declared_nothing_declares_no_posture() {
        assert_eq!(derived_sealing(Some(KEY), None, &[], SealingChoice::Derive), None);
    }

    #[test]
    fn asking_for_a_sign_in_earns_required() {
        assert_eq!(
            derived_sealing(
                Some(KEY),
                None,
                &[offering_needing_credential()],
                SealingChoice::Derive
            )
            .as_deref(),
            Some("required")
        );
    }

    #[test]
    fn declaring_an_integration_earns_preferred() {
        let ww = vec![WorksWith {
            service: "Salesforce".into(),
            ..Default::default()
        }];
        assert_eq!(
            derived_sealing(Some(KEY), Some(&ww), &[], SealingChoice::Derive).as_deref(),
            Some("preferred")
        );
    }

    #[test]
    fn a_credential_need_outranks_an_integration() {
        let ww = vec![WorksWith {
            service: "Salesforce".into(),
            ..Default::default()
        }];
        assert_eq!(
            derived_sealing(
                Some(KEY),
                Some(&ww),
                &[offering_needing_credential()],
                SealingChoice::Derive
            )
            .as_deref(),
            Some("required")
        );
    }

    #[test]
    fn no_encryption_key_means_no_posture_however_it_was_asked_for() {
        for choice in [
            SealingChoice::Derive,
            SealingChoice::Required,
            SealingChoice::Preferred,
        ] {
            assert_eq!(
                derived_sealing(None, None, &[offering_needing_credential()], choice),
                None,
                "a posture is a promise about reading, and there is nothing to read with"
            );
        }
    }

    #[test]
    fn an_operator_can_decline_a_posture_it_would_otherwise_earn() {
        assert_eq!(
            derived_sealing(
                Some(KEY),
                None,
                &[offering_needing_credential()],
                SealingChoice::None
            ),
            None
        );
    }

    #[test]
    fn a_blank_credential_name_is_not_a_declaration() {
        let blank = offering_with_needs(vec![NeedEntry {
            credential: Some("   ".into()),
            ..Default::default()
        }]);
        assert_eq!(derived_sealing(Some(KEY), None, &[blank], SealingChoice::Derive), None);
    }
}
