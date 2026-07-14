# G4 — the merge gate. Evaluated by asdlc-verify as a required check.
#
# Input contract (prepared by the verifier, which has already done signature
# verification and role resolution against the manifest):
#
#   input.change      Change Record (change-record.schema.json)
#   input.head        { "gitCommit": "<40-hex sha of the PR head>" }
#   input.statements  [ { "statement": <in-toto statement>,
#                         "meta": { "sha256": "<statement digest>",
#                                   "signature_verified": <bool>,
#                                   "signer": { "identity": "github:x",
#                                                "roles": ["implementer", ...] } } } ]
#   input.catalogue   parsed controls/catalogue.yaml
#
# The policy never sees raw signatures and never talks to a platform: it is a
# pure function of evidence. Deny rules carry human-readable reasons; the
# verifier surfaces them verbatim on the failed check.

package asdlc.gates.g4

import rego.v1

pt_base := "https://github.com/jvanheerikhuize/asdlc/spec/predicates"

default allow := false

allow if count(deny) == 0

# ---------- integrity: every statement verified, and about this change ------

deny contains msg if {
	some s in input.statements
	not s.meta.signature_verified
	msg := sprintf("statement %s failed signature verification", [s.meta.sha256])
}

deny contains msg if {
	some s in input.statements
	s.statement.predicate.change_id != input.change.id
	msg := sprintf("statement %s belongs to change %s, not %s",
		[s.meta.sha256, s.statement.predicate.change_id, input.change.id])
}

# ---------- intent: exactly one -------------------------------------------

intents := [s | some s in input.statements
	s.statement.predicateType == sprintf("%s/change-intent/v1", [pt_base])]

deny contains "no change-intent/v1 statement" if count(intents) == 0

deny contains "more than one change-intent/v1 statement" if count(intents) > 1

# ---------- classification: present, authorized, after intent ---------------

classifications := [s | some s in input.statements
	s.statement.predicateType == sprintf("%s/classification/v1", [pt_base])]

deny contains "no classification/v1 statement" if count(classifications) == 0

# latest classification governs (reclassification is allowed; history remains)
classification := c.statement.predicate if {
	some c in classifications
	every other in classifications {
		other.statement.predicate.produced_at <= c.statement.predicate.produced_at
	}
}

deny contains msg if {
	some c in classifications
	c.statement.predicate.produced_by.role != "intent-owner"
	msg := "classification must be produced under the intent-owner role"
}

deny contains msg if {
	some c in classifications
	not "intent-owner" in c.meta.signer.roles
	msg := sprintf("classification signer %s does not hold the intent-owner role",
		[c.meta.signer.identity])
}

deny contains "classification predates the change intent" if {
	count(intents) == 1
	classification.produced_at < intents[0].statement.predicate.produced_at
}

deny contains "change is classified as a prohibited AI system" if {
	classification.ai_system_tier == "prohibited"
}

# ---------- required controls: computed from classification -----------------

risk_rank := {"low": 1, "medium": 2, "high": 3}

data_rank := {"none": 0, "internal": 1, "personal": 2, "sensitive": 3}

tier_rank := {"none": 0, "minimal": 1, "limited": 2, "high-risk": 3, "prohibited": 4}

condition_met(cond) if cond.always == true

condition_met(cond) if {
	not cond.always
	risk_ok(cond)
	data_ok(cond)
	tier_ok(cond)
}

risk_ok(cond) if not cond.risk_at_least
risk_ok(cond) if risk_rank[classification.risk] >= risk_rank[cond.risk_at_least]
data_ok(cond) if not cond.data_at_least
data_ok(cond) if data_rank[classification.data] >= data_rank[cond.data_at_least]
tier_ok(cond) if not cond.ai_system_tier_at_least
tier_ok(cond) if tier_rank[classification.ai_system_tier] >= tier_rank[cond.ai_system_tier_at_least]

required_controls := [c | some c in input.catalogue.controls
	c.gate == "G4"
	condition_met(c.activation)]

# ---------- verdicts: pass on head, authorized signer, no standing fail -----

verdicts_for(control_id) := [s | some s in input.statements
	s.statement.predicateType == sprintf("%s/control-verdict/v1", [pt_base])
	s.statement.predicate.control_id == control_id
	some subj in s.statement.subject
	subj.digest.gitCommit == input.head.gitCommit]

deny contains msg if {
	some c in required_controls
	passes := [v | some v in verdicts_for(c.id); v.statement.predicate.verdict == "pass"]
	count(passes) == 0
	msg := sprintf("required control %s has no pass verdict on head commit", [c.id])
}

deny contains msg if {
	some c in required_controls
	some v in verdicts_for(c.id)
	v.statement.predicate.verdict == "fail"
	msg := sprintf("required control %s has a fail verdict on head commit; supersede with new work (waivers arrive in slice 2)", [c.id])
}

deny contains msg if {
	some c in required_controls
	some v in verdicts_for(c.id)
	not v.statement.predicate.produced_by.role in c.verdict_roles
	msg := sprintf("verdict for %s produced under role %s, which the catalogue does not authorize",
		[c.id, v.statement.predicate.produced_by.role])
}

deny contains msg if {
	some c in required_controls
	some v in verdicts_for(c.id)
	not v.statement.predicate.produced_by.role in v.meta.signer.roles
	msg := sprintf("verdict for %s: signer %s does not hold the claimed role %s",
		[c.id, v.meta.signer.identity, v.statement.predicate.produced_by.role])
}

# ---------- human review approval on head -----------------------------------

review_approvals := [s | some s in input.statements
	s.statement.predicateType == sprintf("%s/approval/v1", [pt_base])
	s.statement.predicate.approval_type == "review"
	some subj in s.statement.subject
	subj.digest.gitCommit == input.head.gitCommit]

deny contains "no review approval on head commit" if count(review_approvals) == 0
