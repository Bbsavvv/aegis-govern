from acquisition_engine.license import LicenseEnvelope
from acquisition_engine.notary import ProofNotary
from acquisition_engine.pr_generator_extension import AcquisitionRemediator
from acquisition_engine.sweep import TargetRef
from acquisition_engine.target_auditor import TargetAuditor


def test_target_ref_rejects_localhost_and_file_urls():
    try:
        TargetRef("http://localhost/admin")
        assert False, "expected ValueError"
    except ValueError:
        pass
    try:
        TargetRef("file:///etc/passwd")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_auditor_seals_gdpr_and_ai_act_findings():
    auditor = TargetAuditor()
    report = auditor.audit("https://api.helix-health.de/v1/chat", annual_turnover_eur=400_000_000, sweep_size=4)
    assert report.collection_mode == "simulated_posture_model"
    assert report.target_host == "api.helix-health.de"
    assert report.findings
    citations = {item.citation for item in report.findings}
    assert any("GDPR Art. 44" in c or "44–46" in c for c in citations)
    assert report.expected_exposure_eur > 0
    assert report.statutory_maximum_eur >= 20_000_000
    assert ProofNotary().verify(report.report_id, report.findings, report.integrity)
    assert report.integrity.merkle_root
    assert len(report.integrity.chain) == len(report.findings)


def test_tampered_finding_breaks_seal():
    auditor = TargetAuditor()
    report = auditor.audit("northstar.example", annual_turnover_eur=80_000_000, sweep_size=3)
    report.findings[0].title = "tampered"
    assert ProofNotary().verify(report.report_id, report.findings, report.integrity) is False


def test_acquisition_package_unlocks_only_with_license():
    auditor = TargetAuditor()
    remediator = AcquisitionRemediator()
    report = auditor.audit("https://api.aurora-retail.eu/v1", annual_turnover_eur=120_000_000, sweep_size=3)
    package = remediator.package_report(report)
    assert "Merkle root" in package.executive_summary
    assert package.sealed_patch.locked is True
    assert package.pull_request_ids
    unlocked = remediator.unlock_bundle(package, package.license_key)
    assert unlocked["unlocked"] is True
    assert unlocked["files"]
    try:
        remediator.unlock_bundle(package, "AEGIS-ENT-wrong")
        assert False, "expected PermissionError"
    except PermissionError:
        pass
    envelope = LicenseEnvelope()
    raw = envelope.unlock(package.sealed_patch, package.license_key)
    assert b"report_id" in raw
