"""Collect an access snapshot from Entra ID through Microsoft Graph.

The snapshot is a plain dict so it can be saved to JSON, reviewed later,
and analysed offline (the same format as data/sample_tenant.json).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from .graph_client import GraphClient, GraphError

log = logging.getLogger(__name__)

USER_FIELDS = [
    "id", "displayName", "userPrincipalName", "userType", "accountEnabled",
    "createdDateTime", "externalUserState", "externalUserStateChangeDateTime",
    "onPremisesSyncEnabled",
]


def _collect_users(client: GraphClient) -> list[dict[str, Any]]:
    """Fetch users. signInActivity needs AuditLog.Read.All and Entra ID P1/P2,
    so fall back to a collection without it if the tenant does not allow it."""
    try:
        raw = list(client.get_all("/users", {"$select": ",".join(USER_FIELDS + ["signInActivity"]), "$top": "500"}))
        has_signin = True
    except GraphError as exc:
        log.warning("Could not read signInActivity (%s). Inactivity checks will be skipped.", exc)
        raw = list(client.get_all("/users", {"$select": ",".join(USER_FIELDS), "$top": "500"}))
        has_signin = False

    users = []
    for u in raw:
        activity = u.get("signInActivity") or {}
        users.append({
            "id": u["id"],
            "displayName": u.get("displayName"),
            "userPrincipalName": u.get("userPrincipalName"),
            "userType": u.get("userType") or "Member",
            "accountEnabled": u.get("accountEnabled", True),
            "createdDateTime": u.get("createdDateTime"),
            "externalUserState": u.get("externalUserState"),
            "externalUserStateChangeDateTime": u.get("externalUserStateChangeDateTime"),
            "onPremisesSyncEnabled": bool(u.get("onPremisesSyncEnabled")),
            # Successful interactive or non-interactive sign-in, whichever is newest
            "lastSignInDateTime": max(
                filter(None, [activity.get("lastSuccessfulSignInDateTime"),
                              activity.get("lastSignInDateTime"),
                              activity.get("lastNonInteractiveSignInDateTime")]),
                default=None,
            ) if has_signin else "unknown",
        })
    return users


def _expand_principal(client: GraphClient, principal: dict[str, Any]) -> list[tuple[str, str, str | None]]:
    """Return (principal_id, principal_type, via_group) for a role principal.
    Role-assignable groups are expanded to their transitive user members."""
    ptype = principal.get("@odata.type", "").split(".")[-1]
    if ptype == "group":
        members = client.get_all(f"/groups/{principal['id']}/transitiveMembers/microsoft.graph.user",
                                 {"$select": "id"})
        return [(m["id"], "user", principal.get("displayName")) for m in members]
    return [(principal["id"], ptype or "unknown", None)]


def _collect_roles(client: GraphClient) -> list[dict[str, Any]]:
    definitions = {d["id"]: d for d in client.get_all("/roleManagement/directory/roleDefinitions")}
    assignments: list[dict[str, Any]] = []

    def add(items, kind: str) -> None:
        for a in items:
            role = definitions.get(a["roleDefinitionId"], {})
            principal = a.get("principal") or {"id": a["principalId"]}
            for pid, ptype, via in _expand_principal(client, principal):
                assignments.append({
                    "principalId": pid,
                    "principalType": ptype,
                    "principalName": None if via else principal.get("displayName"),
                    "roleName": role.get("displayName", a["roleDefinitionId"]),
                    "roleTemplateId": role.get("templateId", a["roleDefinitionId"]),
                    "assignmentType": kind,
                    "viaGroup": via,
                })

    add(client.get_all("/roleManagement/directory/roleAssignments", {"$expand": "principal"}), "active")

    # PIM eligible assignments (needs RoleEligibilitySchedule.Read.Directory and Entra ID P2)
    try:
        add(client.get_all("/roleManagement/directory/roleEligibilitySchedules", {"$expand": "principal"}),
            "eligible")
    except GraphError as exc:
        log.warning("Could not read PIM eligible assignments (%s). Continuing without them.", exc)
    return assignments


def _collect_mfa(client: GraphClient) -> dict[str, bool] | None:
    try:
        return {r["id"]: bool(r.get("isMfaRegistered"))
                for r in client.get_all("/reports/authenticationMethods/userRegistrationDetails")}
    except GraphError as exc:
        log.warning("Could not read MFA registration details (%s). MFA check will be skipped.", exc)
        return None


def collect_snapshot(client: GraphClient) -> dict[str, Any]:
    log.info("Collecting users ...")
    users = _collect_users(client)
    log.info("Collecting directory role assignments ...")
    roles = _collect_roles(client)
    log.info("Collecting MFA registration ...")
    mfa = _collect_mfa(client)
    return {
        "collectedAt": datetime.now(timezone.utc).isoformat(),
        "users": users,
        "roleAssignments": roles,
        "mfaRegistered": mfa,
    }
