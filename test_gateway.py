"""
test_gateway.py — Invariant tests for ToolGateway
==================================================
Run with:  pytest test_gateway.py -v

Each test is named after the invariant it protects (matches the Failure Table
in README.md). Every test is structured so that removing the control it covers
makes the test go RED — the test name in the error output tells you exactly
which invariant broke.

Design note: each test injects its own fresh state dicts so tests are fully
isolated; no shared mutable state between tests.
"""

from decimal import Decimal

import pytest

from gateway import (
    GatewayResult,
    Status,
    ToolGateway,
)

# ---------------------------------------------------------------------------
# Helpers — fresh isolated state factories
# ---------------------------------------------------------------------------

def fresh_sessions() -> dict:
    return {
        "sess_alice": {"customer_id": "cust_001", "created_at": 0},
        "sess_bob":   {"customer_id": "cust_002", "created_at": 0},
    }


def fresh_approvals() -> dict:
    return {
        "tok_good": {
            "customer_id": "cust_001",
            "to_account":  "acc_ext_target",
            "amount":      Decimal("200.00"),
            "used":        False,
        },
        "tok_bob": {
            "customer_id": "cust_002",
            "to_account":  "acc_ext_bob",
            "amount":      Decimal("50.00"),
            "used":        False,
        },
    }


def fresh_metrics() -> dict:
    return {
        "get_account_summary":   {"calls": 0, "denied": 0, "errors": 0, "backend_calls": 0},
        "create_support_ticket": {"calls": 0, "denied": 0, "errors": 0, "backend_calls": 0},
        "initiate_transfer":     {"calls": 0, "denied": 0, "errors": 0, "backend_calls": 0},
    }


def make_gw() -> tuple[ToolGateway, dict]:
    """Return a gateway wired to fresh isolated state plus the metrics dict."""
    m = fresh_metrics()
    gw = ToolGateway(
        sessions=fresh_sessions(),
        approvals=fresh_approvals(),
        metric_store=m,
    )
    return gw, m


# ---------------------------------------------------------------------------
# Invariant 1 — IDENTITY ISOLATION (read)
# A session may only read data for its own customer.
# Removing the customer_id == session["customer_id"] check would make this PASS
# when it should DENY → test goes RED.
# ---------------------------------------------------------------------------

class TestIdentityIsolation:
    def test_cross_customer_read_is_denied(self):
        """Alice's session cannot read Bob's account summary."""
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_alice", "get_account_summary", {"customer_id": "cust_002"}
        )
        assert result.status == Status.DENIED
        assert m["get_account_summary"]["backend_calls"] == 0

    def test_cross_customer_write_is_denied(self):
        """Alice's session cannot create a support ticket for Bob."""
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_alice", "create_support_ticket",
            {"customer_id": "cust_002", "subject": "help", "body": "please"},
        )
        assert result.status == Status.DENIED
        assert m["create_support_ticket"]["backend_calls"] == 0

    def test_cross_customer_transfer_is_denied(self):
        """Alice's session cannot initiate a transfer on behalf of Bob."""
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_alice", "initiate_transfer",
            {
                "customer_id":    "cust_002",   # Bob's ID, Alice's session
                "to_account":     "acc_ext_bob",
                "amount":         "50.00",
                "approval_token": "tok_bob",
            },
        )
        assert result.status == Status.DENIED
        assert m["initiate_transfer"]["backend_calls"] == 0

    def test_own_customer_read_is_allowed(self):
        """Control case: Alice reading her own account must succeed."""
        gw, _ = make_gw()
        result = gw.execute_tool(
            "sess_alice", "get_account_summary", {"customer_id": "cust_001"}
        )
        assert result.status == Status.OK


# ---------------------------------------------------------------------------
# Invariant 2 — SESSION AUTHENTICATION
# Unknown or missing sessions are always denied.
# ---------------------------------------------------------------------------

class TestSessionAuthentication:
    def test_unknown_session_is_denied(self):
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_attacker", "get_account_summary", {"customer_id": "cust_001"}
        )
        assert result.status == Status.DENIED
        assert m["get_account_summary"]["backend_calls"] == 0

    def test_empty_session_id_is_denied(self):
        gw, m = make_gw()
        result = gw.execute_tool(
            "", "get_account_summary", {"customer_id": "cust_001"}
        )
        assert result.status == Status.DENIED
        assert m["get_account_summary"]["backend_calls"] == 0


# ---------------------------------------------------------------------------
# Invariant 3 — TOOL ALLOW-LIST
# Only declared tools can be called; anything else is denied at the gate.
# ---------------------------------------------------------------------------

class TestToolAllowList:
    def test_unknown_tool_is_denied(self):
        gw, _ = make_gw()
        result = gw.execute_tool(
            "sess_alice", "drop_database", {"customer_id": "cust_001"}
        )
        assert result.status == Status.DENIED

    def test_empty_tool_name_is_denied(self):
        gw, _ = make_gw()
        result = gw.execute_tool(
            "sess_alice", "", {"customer_id": "cust_001"}
        )
        assert result.status == Status.DENIED

    def test_whitespace_padded_tool_name_is_denied(self):
        """Tool names with leading/trailing whitespace must not bypass the allow-list."""
        gw, _ = make_gw()
        # The gateway strips whitespace, so "  drop_database  " stays unknown.
        result = gw.execute_tool(
            "sess_alice", "  drop_database  ", {"customer_id": "cust_001"}
        )
        assert result.status == Status.DENIED


# ---------------------------------------------------------------------------
# Invariant 4 — REQUIRED PARAMETERS
# A call missing required fields returns ERROR, not DENIED (not a security
# event, but must not reach the backend).
# ---------------------------------------------------------------------------

class TestRequiredParameters:
    def test_missing_subject_and_body_returns_error(self):
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_alice", "create_support_ticket", {"customer_id": "cust_001"}
        )
        assert result.status == Status.ERROR
        assert "subject" in result.message
        assert m["create_support_ticket"]["backend_calls"] == 0

    def test_missing_approval_token_returns_error(self):
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_alice", "initiate_transfer",
            {"customer_id": "cust_001", "to_account": "acc_ext_target", "amount": "200.00"},
        )
        assert result.status == Status.ERROR
        assert m["initiate_transfer"]["backend_calls"] == 0


# ---------------------------------------------------------------------------
# Invariant 5 — APPROVAL TOKEN VALIDATION (transfer-specific)
# Five sub-invariants; each has its own test.
# ---------------------------------------------------------------------------

class TestApprovalTokenValidation:
    def test_unknown_token_is_denied(self):
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_alice", "initiate_transfer",
            {
                "customer_id":    "cust_001",
                "to_account":     "acc_ext_target",
                "amount":         "200.00",
                "approval_token": "tok_does_not_exist",
            },
        )
        assert result.status == Status.DENIED
        assert m["initiate_transfer"]["backend_calls"] == 0

    def test_replayed_token_is_denied(self):
        """A token already marked used=True must be rejected (single-use guarantee)."""
        gw, m = make_gw()
        # First call consumes the token.
        r1 = gw.execute_tool(
            "sess_alice", "initiate_transfer",
            {
                "customer_id":    "cust_001",
                "to_account":     "acc_ext_target",
                "amount":         "200.00",
                "approval_token": "tok_good",
            },
        )
        assert r1.status == Status.OK
        # Second call with the same token must fail.
        r2 = gw.execute_tool(
            "sess_alice", "initiate_transfer",
            {
                "customer_id":    "cust_001",
                "to_account":     "acc_ext_target",
                "amount":         "200.00",
                "approval_token": "tok_good",
            },
        )
        assert r2.status == Status.DENIED
        assert m["initiate_transfer"]["backend_calls"] == 1  # only the first call hit backend

    def test_amount_tamper_is_denied(self):
        """A token for £200 must not authorise a transfer of £999."""
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_alice", "initiate_transfer",
            {
                "customer_id":    "cust_001",
                "to_account":     "acc_ext_target",
                "amount":         "999.00",   # token says 200.00
                "approval_token": "tok_good",
            },
        )
        assert result.status == Status.DENIED
        assert m["initiate_transfer"]["backend_calls"] == 0

    def test_destination_tamper_is_denied(self):
        """A token for acc_ext_target must not authorise a transfer to attacker_acct."""
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_alice", "initiate_transfer",
            {
                "customer_id":    "cust_001",
                "to_account":     "acc_attacker",  # token says acc_ext_target
                "amount":         "200.00",
                "approval_token": "tok_good",
            },
        )
        assert result.status == Status.DENIED
        assert m["initiate_transfer"]["backend_calls"] == 0

    def test_token_owner_mismatch_is_denied(self):
        """Bob's token cannot be used in Alice's session."""
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_alice", "initiate_transfer",   # Alice's session
            {
                "customer_id":    "cust_001",
                "to_account":     "acc_ext_bob",
                "amount":         "50.00",
                "approval_token": "tok_bob",     # Bob's token
            },
        )
        assert result.status == Status.DENIED
        assert m["initiate_transfer"]["backend_calls"] == 0

    def test_garbage_amount_returns_error(self):
        """A non-numeric amount value must return ERROR, not crash."""
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_alice", "initiate_transfer",
            {
                "customer_id":    "cust_001",
                "to_account":     "acc_ext_target",
                "amount":         "two hundred",
                "approval_token": "tok_good",
            },
        )
        assert result.status == Status.ERROR
        assert m["initiate_transfer"]["backend_calls"] == 0


# ---------------------------------------------------------------------------
# Invariant 6 — ALL-OR-NOTHING STATE INJECTION
# Partial injection must raise TypeError at construction time.
# ---------------------------------------------------------------------------

class TestStateInjection:
    def test_partial_injection_raises(self):
        """Passing only one store out of three must be caught immediately."""
        with pytest.raises(TypeError, match="all state stores or none"):
            ToolGateway(sessions=fresh_sessions())

    def test_two_stores_raises(self):
        with pytest.raises(TypeError, match="all state stores or none"):
            ToolGateway(sessions=fresh_sessions(), approvals=fresh_approvals())

    def test_full_injection_ok(self):
        """All three stores provided — must not raise."""
        ToolGateway(
            sessions=fresh_sessions(),
            approvals=fresh_approvals(),
            metric_store=fresh_metrics(),
        )

    def test_no_injection_ok(self):
        """No stores provided — must not raise (uses module globals)."""
        ToolGateway()


# ---------------------------------------------------------------------------
# Happy-path sanity checks
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_valid_account_summary(self):
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_alice", "get_account_summary", {"customer_id": "cust_001"}
        )
        assert result.status == Status.OK
        assert "accounts" in result.data
        assert m["get_account_summary"]["backend_calls"] == 1

    def test_valid_support_ticket(self):
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_bob", "create_support_ticket",
            {"customer_id": "cust_002", "subject": "Card lost", "body": "Help please"},
        )
        assert result.status == Status.OK
        assert "ticket_id" in result.data
        assert m["create_support_ticket"]["backend_calls"] == 1

    def test_valid_transfer(self):
        gw, m = make_gw()
        result = gw.execute_tool(
            "sess_alice", "initiate_transfer",
            {
                "customer_id":    "cust_001",
                "to_account":     "acc_ext_target",
                "amount":         "200.00",
                "approval_token": "tok_good",
            },
        )
        assert result.status == Status.OK
        assert "transfer_id" in result.data
        assert m["initiate_transfer"]["backend_calls"] == 1
