from regulatory_crosswalker.engine import RegulatoryRulesEngine
from tests.factories import make_event, transfer_event


def test_gdpr_flags_unlawful_us_transfer_and_unmasked_special_category():
    engine = RegulatoryRulesEngine()
    findings = engine.evaluate(transfer_event())
    rule_ids = {item.rule_id for item in findings}
    assert "gdpr-art-44-transfer" in rule_ids
    assert "gdpr-art-25-data-minimisation" in rule_ids
    assert "gdpr-art-9-special-category" in rule_ids
    assert "gdpr-art-32-security" in rule_ids
    assert all(item.score >= 50 for item in findings)


def test_eu_ai_act_flags_undisclosed_chat_and_missing_oversight():
    engine = RegulatoryRulesEngine()
    event = make_event(
        risk={
            "model_risk_class": "high",
            "annex_iii_use_case": "creditworthiness",
            "human_oversight": False,
            "automated_decision": True,
            "audit_logging_enabled": False,
        }
    )
    event.model_call.disclosed_as_ai = False
    findings = engine.evaluate(event)
    rule_ids = {item.rule_id for item in findings}
    assert "eu-ai-act-art-14-oversight" in rule_ids
    assert "eu-ai-act-art-50-transparency" in rule_ids
    assert "eu-ai-act-art-12-logging" in rule_ids


def test_prohibited_social_scoring_is_critical():
    engine = RegulatoryRulesEngine()
    event = make_event(risk={"social_scoring": True, "purpose": "ranking"})
    findings = engine.evaluate(event)
    social = next(item for item in findings if item.rule_id == "eu-ai-act-art-5-social-scoring")
    assert social.severity.value == "critical"
