import json
from datetime import datetime, timezone
from importlib import resources

from entra_access_review.cli import main
from entra_access_review.rules import Config, analyse

NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)
GA = "62e90394-69f5-4237-9190-012177145e10"
UA = "fe930be7-5e62-47db-91af-98c3a49a38b1"


def user(uid, last="2026-10-19T00:00:00Z", **kw):
    base = dict(id=uid, displayName=uid, userPrincipalName=f"{uid}@test.example", userType="Member",
                accountEnabled=True, createdDateTime="2025-01-01T00:00:00Z", externalUserState=None,
                externalUserStateChangeDateTime=None, onPremisesSyncEnabled=False, lastSignInDateTime=last)
    return {**base, **kw}


def role(uid, template=GA, name="Global Administrator", kind="active", ptype="user", via=None):
    return dict(principalId=uid, principalType=ptype, principalName=None, roleName=name,
                roleTemplateId=template, assignmentType=kind, viaGroup=via)


def run(users, roles=(), mfa=None, **cfg):
    snap = {"users": users, "roleAssignments": list(roles),
            "mfaRegistered": mfa if mfa is not None else {u["id"]: True for u in users}}
    return analyse(snap, Config(now=NOW, **cfg))


def ids(findings):
    return {(f.rule_id, f.principal.split("@")[0]) for f in findings}


def test_clean_tenant_has_no_findings():
    users = [user("a"), user("b")]
    assert run(users, [role("a", kind="eligible"), role("b", kind="eligible")]) == []


def test_inactive_and_privileged_inactive():
    found = run([user("old", last="2026-05-01T00:00:00Z"), user("admin", last="2026-01-01T00:00:00Z")],
                [role("admin", UA, "User Administrator")])
    sev = {f.principal.split("@")[0]: f.severity for f in found if f.rule_id == "EAR-001"}
    assert sev == {"old": "medium", "admin": "high"}


def test_inactive_threshold_is_configurable():
    users = [user("x", last="2026-08-01T00:00:00Z")]  # 80 days
    assert not [f for f in run(users) if f.rule_id == "EAR-001"]
    assert [f for f in run(users, inactive_days=60) if f.rule_id == "EAR-001"]


def test_never_signed_in_respects_grace_period():
    fresh = user("new", last=None, createdDateTime="2026-10-10T00:00:00Z")
    stale = user("stale", last=None, createdDateTime="2026-01-01T00:00:00Z")
    assert ids(run([fresh, stale])) == {("EAR-002", "stale")}


def test_disabled_account_with_role():
    found = run([user("gone", accountEnabled=False)], [role("gone", UA, "User Administrator")])
    assert ("EAR-003", "gone") in ids(found)


def test_guest_with_global_admin_is_critical():
    found = run([user("g", userType="Guest")], [role("g")])
    f = next(f for f in found if f.rule_id == "EAR-004")
    assert f.severity == "critical"


def test_pending_guest_flagged_once():
    g = user("g", last=None, userType="Guest", externalUserState="PendingAcceptance",
             externalUserStateChangeDateTime="2026-07-01T00:00:00Z", createdDateTime="2026-07-01T00:00:00Z")
    assert {f.rule_id for f in run([g])} == {"EAR-005"}


def test_privileged_without_mfa():
    found = run([user("a")], [role("a", UA, "User Administrator")], mfa={"a": False})
    assert ("EAR-006", "a") in ids(found)


def test_mfa_check_skipped_when_data_missing():
    snap = {"users": [user("a")], "roleAssignments": [role("a", UA, "User Administrator")], "mfaRegistered": None}
    assert not [f for f in analyse(snap, Config(now=NOW)) if f.rule_id == "EAR-006"]


def test_break_glass_excluded_from_standing_access():
    users = [user("bg"), user("admin")]
    found = run(users, [role("bg"), role("admin")], break_glass={"bg@test.example"})
    standing = {p for r, p in ids(found) if r == "EAR-007"}
    assert standing == {"admin"}


def test_synced_tier0_account():
    found = run([user("hybrid", onPremisesSyncEnabled=True)], [role("hybrid", kind="eligible")])
    assert ("EAR-008", "hybrid") in ids(found)


def test_global_admin_count_limits():
    many = [user(f"u{i}") for i in range(7)]
    assert any(f.title.startswith("Too many") for f in run(many, [role(u["id"], kind="eligible") for u in many]))
    assert any(f.title.startswith("Too few") for f in run([user("solo")], [role("solo", kind="eligible")]))


def test_service_principal_with_tier0_role():
    found = run([user("a"), user("b")], [role("a", kind="eligible"), role("b", kind="eligible"),
                                         role("sp1", ptype="servicePrincipal")])
    f = next(f for f in found if f.rule_id == "EAR-010")
    assert f.severity == "high"


def test_excessive_roles():
    roles = [role("a", t, n) for t, n in [
        (UA, "User Administrator"),
        ("29232cdf-9323-42fd-ade2-1d097af3e4de", "Exchange Administrator"),
        ("f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "SharePoint Administrator")]]
    assert ("EAR-011", "a") in ids(run([user("a")], roles))


def test_findings_sorted_by_severity():
    found = run([user("g", userType="Guest"), user("old", last="2026-01-01T00:00:00Z")], [role("g")])
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert [order[f.severity] for f in found] == sorted(order[f.severity] for f in found)


def test_demo_end_to_end(tmp_path):
    code = main(["--demo", "--out", str(tmp_path), "--fail-on", "critical"])
    assert code == 2  # the demo tenant contains critical findings on purpose
    data = json.loads((tmp_path / "findings.json").read_text())
    assert data["summary"]["bySeverity"]["critical"] == 3
    assert (tmp_path / "report.html").exists() and (tmp_path / "findings.csv").exists()


def test_sample_data_is_bundled():
    raw = resources.files("entra_access_review.data").joinpath("sample_tenant.json").read_text()
    assert json.loads(raw)["users"]
