"""Test the collector against a fake Graph client (no network)."""

from entra_access_review.collector import collect_snapshot
from entra_access_review.graph_client import GraphError

GA = "62e90394-69f5-4237-9190-012177145e10"


class FakeGraph:
    def __init__(self, signin_allowed=True, pim_allowed=True):
        self.signin_allowed = signin_allowed
        self.pim_allowed = pim_allowed

    def get_all(self, path, params=None):
        if path == "/users":
            if "signInActivity" in params["$select"] and not self.signin_allowed:
                raise GraphError("403")
            return iter([{"id": "u1", "displayName": "A", "userPrincipalName": "a@x", "userType": "Member",
                          "accountEnabled": True, "createdDateTime": "2025-01-01T00:00:00Z",
                          "signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z",
                                             "lastNonInteractiveSignInDateTime": "2026-03-01T00:00:00Z"}},
                         {"id": "u2", "userPrincipalName": "b@x", "accountEnabled": True}])
        if path == "/roleManagement/directory/roleDefinitions":
            return iter([{"id": GA, "templateId": GA, "displayName": "Global Administrator"}])
        if path == "/roleManagement/directory/roleAssignments":
            return iter([
                {"roleDefinitionId": GA, "principalId": "u1",
                 "principal": {"@odata.type": "#microsoft.graph.user", "id": "u1", "displayName": "A"}},
                {"roleDefinitionId": GA, "principalId": "g1",
                 "principal": {"@odata.type": "#microsoft.graph.group", "id": "g1", "displayName": "Admins"}},
            ])
        if path == "/roleManagement/directory/roleEligibilitySchedules":
            if not self.pim_allowed:
                raise GraphError("403")
            return iter([])
        if path == "/groups/g1/transitiveMembers/microsoft.graph.user":
            return iter([{"id": "u2"}])
        if path == "/reports/authenticationMethods/userRegistrationDetails":
            return iter([{"id": "u1", "isMfaRegistered": True}])
        raise AssertionError(path)


def test_collects_and_expands_groups():
    snap = collect_snapshot(FakeGraph())
    users = {u["id"]: u for u in snap["users"]}
    assert users["u1"]["lastSignInDateTime"] == "2026-03-01T00:00:00Z"  # newest of the sign-in fields
    assert users["u2"]["lastSignInDateTime"] is None
    via = {a["principalId"]: a["viaGroup"] for a in snap["roleAssignments"]}
    assert via == {"u1": None, "u2": "Admins"}
    assert snap["mfaRegistered"] == {"u1": True}


def test_degrades_gracefully_without_premium_data():
    snap = collect_snapshot(FakeGraph(signin_allowed=False, pim_allowed=False))
    assert all(u["lastSignInDateTime"] == "unknown" for u in snap["users"])
    assert len(snap["roleAssignments"]) == 2
