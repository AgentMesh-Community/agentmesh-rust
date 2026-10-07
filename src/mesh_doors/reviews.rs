//! `mesh.reviews()`: a party's signed judgment of the other side of an
//! engagement (platform-services/reviews.json). The TypeScript SDK's
//! `reviews-door.ts`.
//!
//! The review is signed here, by this agent's own key, over the same bytes
//! the adapter signs and the platform checks: `agent-sow-review-v1` (or
//! `agent-sow-buyer-review-v1` about a buyer) and the canonical JSON of the
//! review, and `fdbk-value-v1:...` for a value judgment. The signature is the
//! evidence the reputation bureau keeps, which is why a review is not a
//! platform request signed only as a request.

use serde_json::{json, Map, Value};

use crate::client::AgentMesh;
use crate::services::*;

use super::{agent_of, json_body};

/// What the platform answered, as the definition's refusals.
fn refusal_of(status: u16, said: &str) -> &'static str {
    let s = said.to_lowercase();
    if status == 403 && (s.contains("relationship") || s.contains("engagement or agreement")) {
        return "NO_RELATIONSHIP";
    }
    if status == 422 && ["time and materials", "no_charge", "names deliverables", "file a review", "value judgment"].iter().any(|w| s.contains(w)) {
        return "WRONG_KIND";
    }
    if status == 400 || status == 422 {
        return "INPUT_INVALID";
    }
    "UNAVAILABLE"
}

/// How JavaScript writes a number, which the value judgment's signed string carries.
pub(crate) fn js_number(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e21 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// The string a value judgment is signed over.
#[allow(clippy::too_many_arguments)]
pub(crate) fn value_canonical(interaction: &str, seller: &str, offering: &str, outcome: &str, amount: Option<f64>, currency: &str, units: Option<f64>, at: &str) -> String {
    [
        "fdbk-value-v1",
        interaction,
        seller,
        offering,
        outcome,
        &amount.map(js_number).unwrap_or_default(),
        currency,
        &units.map(js_number).unwrap_or_default(),
        at,
    ]
    .join(":")
}

async fn post(mesh: &AgentMesh, path: &str, body: Value) -> Result<(u16, Value), String> {
    let p = mesh.platform();
    let res = p.transport.post_json(&format!("{}/v1{path}", p.api), None, body.to_string()).await?;
    Ok((res.status, json_body(&res.body)))
}

impl ReviewsRequests for ReviewsService<'_> {
    async fn file(&self, input: ReviewsFileInput) -> Result<ReviewsFileResult, ServiceError> {
        let about = input.about.clone().unwrap_or_else(|| "seller".to_string());
        if input.verdict == "rejected" && input.reason.as_deref().map(str::trim).unwrap_or("").is_empty() {
            return Err(ReviewsFileRefusal::InputInvalid.refuse("A rejection needs a reason: an unreasoned rejection is not a review."));
        }
        let other = agent_of(self.mesh, &input.of_agent).await.map_err(|_| ReviewsFileRefusal::NotFound.refuse(format!("No agent answers to {}.", input.of_agent.trim())))?.agent_id;
        let me = self.mesh.id().to_string();
        let buyer = about == "buyer";
        let mut signed = Map::new();
        signed.insert("client".into(), json!(if buyer { &other } else { &me }));
        signed.insert("seller".into(), json!(if buyer { &me } else { &other }));
        signed.insert("offering".into(), json!(input.offering.trim()));
        signed.insert("verdict".into(), json!(input.verdict));
        signed.insert("at".into(), json!(now_js()));
        if let Some(r) = input.reason.as_ref().filter(|r| !r.is_empty()) {
            signed.insert("reason".into(), json!(r));
        }
        if let Some(t) = input.task_id.as_ref().filter(|t| !t.is_empty()) {
            signed.insert("task_id".into(), json!(t));
        }
        let tag = if buyer { "agent-sow-buyer-review-v1" } else { "agent-sow-review-v1" };
        let sig = self.mesh.sign_detached(&format!("{tag}\n{}", crate::identity::canonical_json(&Value::Object(signed.clone()))));
        let mut body = signed;
        body.insert("sig".into(), json!(sig));
        if buyer {
            body.insert("about".into(), json!("client"));
        }
        let (status, out) = post(self.mesh, "/reviews", Value::Object(body)).await.map_err(|w| ReviewsFileRefusal::Unavailable.refuse(w))?;
        if status != 200 {
            let said = out.get("error").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| format!("HTTP {status}"));
            let code = ReviewsFileRefusal::from_code(refusal_of(status, &said)).unwrap_or(ReviewsFileRefusal::Unavailable);
            return Err(code.refuse(said));
        }
        Ok(ReviewsFileResult {
            filed: input.verdict,
            about: if buyer { "buyer" } else { "seller" }.to_string(),
            review_number: out.get("count").and_then(Value::as_i64),
            note: "Append-only: a changed mind is a second review.".to_string(),
        })
    }

    async fn rate(&self, input: ReviewsRateInput) -> Result<ReviewsRateResult, ServiceError> {
        let outcome = if input.judgment == "ok" { "VALUE_OK" } else { "VALUE_POOR" };
        if outcome == "VALUE_POOR" && input.reason.as_deref().map(str::trim).unwrap_or("").is_empty() {
            return Err(ReviewsRateRefusal::InputInvalid.refuse("A poor judgment needs a reason: an unreasoned negative judgment is not evidence."));
        }
        if input.amount.is_some() && input.currency.as_deref().unwrap_or("").is_empty() {
            return Err(ReviewsRateRefusal::InputInvalid.refuse("An amount needs a currency, so the number means something."));
        }
        let seller = agent_of(self.mesh, &input.of_agent).await.map_err(|_| ReviewsRateRefusal::NotFound.refuse(format!("No agent answers to {}.", input.of_agent.trim())))?.agent_id;
        let me = self.mesh.id().to_string();
        let offering = input.offering.trim().to_string();
        let at = now_js();
        let interaction = input.interaction_id.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| format!("engagement:{me}:{seller}:{offering}"));
        let currency = input.currency.clone().unwrap_or_default();
        let canonical = value_canonical(&interaction, &seller, &offering, outcome, input.amount, &currency, input.units, &at);
        let mut body = Map::new();
        body.insert("client".into(), json!(me));
        body.insert("seller".into(), json!(seller));
        body.insert("offering".into(), json!(offering));
        body.insert("outcome".into(), json!(outcome));
        body.insert("at".into(), json!(at));
        body.insert("interaction_id".into(), json!(interaction));
        body.insert("sig".into(), json!(self.mesh.sign_detached(&canonical)));
        if let Some(a) = input.amount {
            body.insert("amount".into(), json!(a));
            body.insert("currency".into(), json!(currency));
        }
        if let Some(u) = input.units {
            body.insert("units".into(), json!(u));
        }
        if let Some(r) = input.reason.as_ref().filter(|r| !r.is_empty()) {
            body.insert("reason".into(), json!(r));
        }
        let (status, out) = post(self.mesh, "/value-judgments", Value::Object(body)).await.map_err(|w| ReviewsRateRefusal::Unavailable.refuse(w))?;
        if status != 200 {
            let said = out.get("error").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| format!("HTTP {status}"));
            let code = ReviewsRateRefusal::from_code(refusal_of(status, &said)).unwrap_or(ReviewsRateRefusal::Unavailable);
            return Err(code.refuse(said));
        }
        let carries = out.get("carries_amount").and_then(Value::as_bool).unwrap_or(false);
        let covers = carries.then(|| {
            let mut c = Map::new();
            c.insert("amount".into(), json!(input.amount));
            c.insert("currency".into(), json!(currency));
            if let Some(u) = input.units {
                c.insert("units".into(), json!(u));
            }
            c
        });
        Ok(ReviewsRateResult {
            filed: if outcome == "VALUE_OK" { "worth it" } else { "not worth it" }.to_string(),
            judgment_number: out.get("count").and_then(Value::as_i64),
            covers,
            note: if carries {
                "Append-only; the signature covers the amount.".to_string()
            } else {
                "Append-only; it names no amount. Give amount and currency to say what the spend was.".to_string()
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_judgment_is_signed_over_what_the_platform_checks() {
        assert_eq!(js_number(12.0), "12");
        assert_eq!(js_number(12.5), "12.5");
        assert_eq!(js_number(0.1), "0.1");
        assert_eq!(
            value_canonical("engagement:UA:US:chat", "US", "chat", "VALUE_OK", Some(12.0), "USD", None, "2026-10-05T18:00:00.000Z"),
            "fdbk-value-v1:engagement:UA:US:chat:US:chat:VALUE_OK:12:USD::2026-10-05T18:00:00.000Z"
        );
        assert_eq!(
            value_canonical("i", "US", "chat", "VALUE_POOR", None, "", None, "t"),
            "fdbk-value-v1:i:US:chat:VALUE_POOR::::t"
        );
    }

    #[test]
    fn the_platforms_answers_become_the_definitions_refusals() {
        assert_eq!(refusal_of(403, "No engagement or agreement between these parties"), "NO_RELATIONSHIP");
        assert_eq!(refusal_of(422, "A no_charge offering takes a value judgment"), "WRONG_KIND");
        assert_eq!(refusal_of(400, "verdict is wrong"), "INPUT_INVALID");
        assert_eq!(refusal_of(503, "down"), "UNAVAILABLE");
    }
}
