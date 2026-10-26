"""Access review rules.

Each rule looks at a snapshot (see collector.py) and returns findings.
Rules are pure functions, so they are easy to test and to extend.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# Tier 0: roles that can take over the whole tenant
TIER0_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
}

# Other highly privileged roles
PRIVILEGED_ROLES = {
    **TIER0_ROLES,
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Config:
    inactive_days: int = 90
    never_signed_in_grace_days: int = 30
    pending_guest_days: int = 30
    max_global_admins: int = 5
    min_global_admins: int = 2
    excessive_role_count: int = 3
    break_glass: set[str] = field(default_factory=set)  # UPNs of documented emergency access accounts
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Finding:
    severity: str
    rule_id: str
    title: str
    principal: str
    detail: str
    recommendation: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _parse(ts: str | None) -> datetime | None:
    if not ts or ts == "unknown":
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _is_tier0(a: dict[str, Any]) -> bool:
    return a["roleTemplateId"] in TIER0_ROLES or a["roleName"] in TIER0_ROLES.values()


def _is_privileged(a: dict[str, Any]) -> bool:
    return a["roleTemplateId"] in PRIVILEGED_ROLES or a["roleName"] in PRIVILEGED_ROLES.values()


class Context:
    """Indexes the snapshot so rules can look things up quickly."""

    def __init__(self, snapshot: dict[str, Any], cfg: Config):
        self.cfg = cfg
        self.users = {u["id"]: u for u in snapshot["users"]}
        self.assignments = snapshot["roleAssignments"]
        self.mfa = snapshot.get("mfaRegistered")
        self.signin_known = any(u.get("lastSignInDateTime") != "unknown" for u in snapshot["users"])
        self.roles_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for a in self.assignments:
            if a["principalType"] == "user":
                self.roles_by_user[a["principalId"]].append(a)

    def label(self, user_id: str) -> str:
        u = self.users.get(user_id)
        return u["userPrincipalName"] if u else user_id

    def role_names(self, user_id: str, pred: Callable[[dict[str, Any]], bool] = lambda a: True) -> list[str]:
        return sorted({a["roleName"] for a in self.roles_by_user.get(user_id, []) if pred(a)})

    def days_since(self, ts: str | None) -> int | None:
        dt = _parse(ts)
        return None if dt is None else (self.cfg.now - dt).days


# --------------------------------------------------------------------------- rules

def inactive_accounts(ctx: Context) -> list[Finding]:
    if not ctx.signin_known:
        return []
    out = []
    for u in ctx.users.values():
        if not u["accountEnabled"] or u.get("lastSignInDateTime") is None:
            continue
        days = ctx.days_since(u["lastSignInDateTime"])
        if days is None or days < ctx.cfg.inactive_days:
            continue
        priv = ctx.role_names(u["id"], _is_privileged)
        guest = u["userType"] == "Guest"
        out.append(Finding(
            severity="high" if priv else "medium",
            rule_id="EAR-001",
            title="Inactive privileged account" if priv else ("Inactive guest" if guest else "Inactive account"),
            principal=ctx.label(u["id"]),
            detail=f"No successful sign-in for {days} days." + (f" Holds: {', '.join(priv)}." if priv else ""),
            recommendation="Confirm with the manager or sponsor; disable the account, then delete after the "
                           "retention period. Remove privileged roles immediately.",
        ))
    return out


def never_signed_in(ctx: Context) -> list[Finding]:
    if not ctx.signin_known:
        return []
    out = []
    for u in ctx.users.values():
        if not u["accountEnabled"] or u.get("lastSignInDateTime") is not None:
            continue
        if u.get("externalUserState") == "PendingAcceptance":
            continue  # covered by EAR-005
        age = ctx.days_since(u.get("createdDateTime"))
        if age is None or age < ctx.cfg.never_signed_in_grace_days:
            continue
        out.append(Finding(
            severity="medium",
            rule_id="EAR-002",
            title="Account has never signed in",
            principal=ctx.label(u["id"]),
            detail=f"Created {age} days ago and never used.",
            recommendation="Verify the account is still needed (onboarding that never happened, test account). "
                           "Disable if not.",
        ))
    return out


def disabled_with_roles(ctx: Context) -> list[Finding]:
    out = []
    for uid in ctx.roles_by_user:
        u = ctx.users.get(uid)
        if u and not u["accountEnabled"]:
            out.append(Finding(
                severity="medium",
                rule_id="EAR-003",
                title="Disabled account still holds directory roles",
                principal=ctx.label(uid),
                detail=f"Roles: {', '.join(ctx.role_names(uid))}.",
                recommendation="Remove role assignments as part of the leaver process so the access cannot "
                               "come back if the account is re-enabled.",
            ))
    return out


def privileged_guests(ctx: Context) -> list[Finding]:
    out = []
    for uid in ctx.roles_by_user:
        u = ctx.users.get(uid)
        if not u or u["userType"] != "Guest":
            continue
        tier0 = ctx.role_names(uid, _is_tier0)
        out.append(Finding(
            severity="critical" if tier0 else "high",
            rule_id="EAR-004",
            title="Guest user holds a directory role",
            principal=ctx.label(uid),
            detail=f"Roles: {', '.join(ctx.role_names(uid))}. The identity is controlled by another organization.",
            recommendation="Remove the role, or replace the guest with a managed internal admin account "
                           "covered by your own MFA and lifecycle controls.",
        ))
    return out


def pending_guest_invites(ctx: Context) -> list[Finding]:
    out = []
    for u in ctx.users.values():
        if u["userType"] != "Guest" or u.get("externalUserState") != "PendingAcceptance":
            continue
        days = ctx.days_since(u.get("externalUserStateChangeDateTime") or u.get("createdDateTime"))
        if days is None or days < ctx.cfg.pending_guest_days:
            continue
        out.append(Finding(
            severity="low",
            rule_id="EAR-005",
            title="Guest invitation never accepted",
            principal=ctx.label(u["id"]),
            detail=f"Invitation pending for {days} days.",
            recommendation="Delete stale invitations; invite again if the collaboration is still needed.",
        ))
    return out


def privileged_without_mfa(ctx: Context) -> list[Finding]:
    if ctx.mfa is None:
        return []
    out = []
    for uid in ctx.roles_by_user:
        priv = ctx.role_names(uid, _is_privileged)
        if priv and uid in ctx.users and not ctx.mfa.get(uid, False):
            out.append(Finding(
                severity="critical",
                rule_id="EAR-006",
                title="Privileged account without registered MFA",
                principal=ctx.label(uid),
                detail=f"Holds: {', '.join(priv)}. No MFA method registered.",
                recommendation="Require phishing-resistant MFA for all admin roles with Conditional Access; "
                               "block the account until MFA is registered.",
            ))
    return out


def standing_tier0_access(ctx: Context) -> list[Finding]:
    eligible_seen = any(a["assignmentType"] == "eligible" for a in ctx.assignments)
    out = []
    for uid, roles in ctx.roles_by_user.items():
        active = sorted({a["roleName"] for a in roles if a["assignmentType"] == "active" and _is_tier0(a)})
        if active and uid in ctx.users:
            if ctx.users[uid]["userPrincipalName"].lower() in ctx.cfg.break_glass:
                continue  # documented emergency access account, permanent by design
            out.append(Finding(
                severity="medium",
                rule_id="EAR-007",
                title="Permanent (standing) Tier 0 role assignment",
                principal=ctx.label(uid),
                detail=f"Permanently active: {', '.join(active)}."
                       + ("" if eligible_seen else " No PIM eligible assignments found in tenant."),
                recommendation="Make the assignment eligible in Privileged Identity Management (just-in-time "
                               "with approval). Only documented break-glass accounts should be permanent.",
            ))
    return out


def synced_tier0(ctx: Context) -> list[Finding]:
    out = []
    for uid in ctx.roles_by_user:
        u = ctx.users.get(uid)
        tier0 = ctx.role_names(uid, _is_tier0)
        if u and tier0 and u.get("onPremisesSyncEnabled"):
            out.append(Finding(
                severity="high",
                rule_id="EAR-008",
                title="On-premises synced account holds a Tier 0 role",
                principal=ctx.label(uid),
                detail=f"Holds: {', '.join(tier0)}. A compromise of Active Directory can lead to cloud takeover.",
                recommendation="Use separate cloud-only admin accounts for Entra ID administration.",
            ))
    return out


def global_admin_count(ctx: Context) -> list[Finding]:
    gas = {a["principalId"] for a in ctx.assignments
           if a["roleTemplateId"] == "62e90394-69f5-4237-9190-012177145e10"
           or a["roleName"] == "Global Administrator"}
    n = len(gas)
    if n > ctx.cfg.max_global_admins:
        return [Finding("high", "EAR-009", "Too many Global Administrators", "Tenant",
                        f"{n} principals hold Global Administrator (recommended: at most "
                        f"{ctx.cfg.max_global_admins}).",
                        "Move admins to least-privileged roles that cover their actual tasks.")]
    if 0 < n < ctx.cfg.min_global_admins:  # 0 means role data is missing, not a real tenant state
        return [Finding("low", "EAR-009", "Too few Global Administrators", "Tenant",
                        f"Only {n} Global Administrator(s).",
                        "Keep at least two, including a monitored break-glass account, to avoid lock-out.")]
    return []


def privileged_service_principals(ctx: Context) -> list[Finding]:
    out = []
    seen: set[tuple[str, str]] = set()
    for a in ctx.assignments:
        if a["principalType"] == "servicePrincipal" and _is_privileged(a):
            key = (a["principalId"], a["roleName"])
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                severity="high" if _is_tier0(a) else "medium",
                rule_id="EAR-010",
                title="Application holds a privileged directory role",
                principal=a.get("principalName") or a["principalId"],
                detail=f"Role: {a['roleName']}. Anyone who controls the app's credentials gets this access.",
                recommendation="Replace the role with narrowly scoped Graph application permissions, and "
                               "review who owns the app and its credentials.",
            ))
    return out


def excessive_roles(ctx: Context) -> list[Finding]:
    out = []
    for uid in ctx.roles_by_user:
        priv = ctx.role_names(uid, _is_privileged)
        if uid in ctx.users and len(priv) >= ctx.cfg.excessive_role_count:
            out.append(Finding(
                severity="medium",
                rule_id="EAR-011",
                title="Account accumulates many privileged roles",
                principal=ctx.label(uid),
                detail=f"{len(priv)} privileged roles: {', '.join(priv)}.",
                recommendation="Review against the person's current tasks (role creep). Remove roles that "
                               "are no longer needed.",
            ))
    return out


def roles_via_group(ctx: Context) -> list[Finding]:
    groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    for a in ctx.assignments:
        if a.get("viaGroup") and _is_tier0(a):
            groups[(a["viaGroup"], a["roleName"])].add(a["principalId"])
    return [Finding(
        severity="low",
        rule_id="EAR-012",
        title="Tier 0 role granted through a group",
        principal=group,
        detail=f"{role} via group membership (members: {len(members)}). Group owners can grant this role.",
        recommendation="Make sure the group is role-assignable, has few owners, and that membership is "
                       "covered by access reviews.",
    ) for (group, role), members in groups.items()]


RULES: list[Callable[[Context], list[Finding]]] = [
    inactive_accounts, never_signed_in, disabled_with_roles, privileged_guests,
    pending_guest_invites, privileged_without_mfa, standing_tier0_access, synced_tier0,
    global_admin_count, privileged_service_principals, excessive_roles, roles_via_group,
]


def analyse(snapshot: dict[str, Any], cfg: Config | None = None) -> list[Finding]:
    ctx = Context(snapshot, cfg or Config())
    findings = [f for rule in RULES for f in rule(ctx)]
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.principal))
