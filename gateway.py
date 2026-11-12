"""
LLM Tool Gateway — Digital Bank Take-Home Exercise
===================================================
Safety properties enforced by this module
  1. Identity isolation  – a session can only read/act on its own customer.
  2. Transfer authorization – every transfer must carry a pre-issued
     approval_token that matches customer, amount, and destination exactly.
  3. Prompt-agnostic enforcement – all checks run on structured data inside
     execute_tool(); no prompt text is ever evaluated as a security signal.

Nothing here is a real bank. All state is in-process dictionaries.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger("gateway")

# ---------------------------------------------------------------------------
# 1. MOCK STATE
# ---------------------------------------------------------------------------

# session_store: session_id → {customer_id, created_at}
session_store: dict[str, dict[str, Any]] = {
    "sess_alice": {"customer_id": "cust_001", "created_at": 1_700_000_000},
    "sess_bob":   {"customer_id": "cust_002", "created_at": 1_700_000_001},
}

# approval_store: approval_token → {customer_id, to_account, amount, used}
#
# Decision 1 (rewrite): amounts are stored as decimal.Decimal so that:
#   • Comparison is exact — no floating-point rounding (0.1 + 0.2 ≠ 0.3).
#   • Callers may supply int, float, or string; _validate_transfer_approval
#     normalises all three via Decimal() before comparing.
#   • The human-readable scale (£500.00, not 50000) makes accidental
#     off-by-100 errors visible at a glance in the stub data.
#
# Tokens are single-use (see Decision 2 note in _validate_transfer_approval).
approval_store: dict[str, dict[str, Any]] = {
    "tok_abc123": {
        "customer_id": "cust_001",
        "to_account":  "acc_external_99",
        "amount":      Decimal("500.00"),   # £500.00
        "used":        False,
    },
    "tok_def456": {
        "customer_id": "cust_002",
        "to_account":  "acc_external_77",
        "amount":      Decimal("100.00"),   # £100.00
        "used":        False,
    },
}

# accounts: customer_id → list of account dicts
_accounts: dict[str, list[dict[str, Any]]] = {
    "cust_001": [
        {"account_id": "acc_001a", "type": "current",  "balance_cents": 1_234_56},
        {"account_id": "acc_001b", "type": "savings",  "balance_cents": 9_999_00},
    ],
    "cust_002": [
        {"account_id": "acc_002a", "type": "current",  "balance_cents":   500_00},
    ],
}

# metrics: simple per-tool counters
# 'calls'         = execute_tool reached the allow-list check
# 'denied'        = gateway rejected the call
# 'errors'        = missing param or backend exception
# 'backend_calls' = backend stub was actually invoked (all checks passed)
metrics: dict[str, dict[str, int]] = {
    "get_account_summary":  {"calls": 0, "denied": 0, "errors": 0, "backend_calls": 0},
    "create_support_ticket":{"calls": 0, "denied": 0, "errors": 0, "backend_calls": 0},
    "initiate_transfer":    {"calls": 0, "denied": 0, "errors": 0, "backend_calls": 0},
}


# ---------------------------------------------------------------------------
# 2. RESULT TYPE
# ---------------------------------------------------------------------------

class Status(str, Enum):
    OK      = "ok"
    DENIED  = "denied"
    ERROR   = "error"


@dataclass
class GatewayResult:
    status:  Status
    data:    dict[str, Any] = field(default_factory=dict)
    message: str = ""

    def __repr__(self) -> str:
        return f"GatewayResult(status={self.status}, message={self.message!r}, data={self.data})"


# ---------------------------------------------------------------------------
# 3. STUBBED BACKEND TOOLS
# ---------------------------------------------------------------------------

def get_account_summary(customer_id: str) -> dict[str, Any]:
    """Return a stub account summary for *customer_id*."""
    accounts = _accounts.get(customer_id, [])
    total = sum(a["balance_cents"] for a in accounts)
    return {
        "customer_id": customer_id,
        "accounts": accounts,
        "total_balance_cents": total,
    }


def create_support_ticket(customer_id: str, subject: str, body: str) -> dict[str, Any]:
    """Create a stub support ticket; returns a generated ticket_id."""
    ticket_id = "tkt_" + hashlib.sha1(
        f"{customer_id}{subject}{time.time()}".encode()
    ).hexdigest()[:8]
    return {
        "ticket_id":   ticket_id,
        "customer_id": customer_id,
        "subject":     subject,
        "body":        body,
        "status":      "open",
        "created_at":  int(time.time()),
    }


def initiate_transfer(
    customer_id: str,
    to_account:  str,
    amount:      Decimal,       # e.g. Decimal("500.00")
    approval_token: str,
) -> dict[str, Any]:
    """
    Execute a stub transfer.

    NOTE: approval validation is handled by the Gateway *before* this
    function is ever called. This stub simply records the action.
    """
    transfer_id = "txn_" + uuid.uuid4().hex[:10]
    return {
        "transfer_id":      transfer_id,
        "customer_id":      customer_id,
        "to_account":       to_account,
        "amount_cents":     amount,
        "approval_token":   approval_token,
        "status":           "pending",
        "submitted_at":     int(time.time()),
    }


# ---------------------------------------------------------------------------
# 4. GATEWAY CLASS
# ---------------------------------------------------------------------------

# Required parameters for each tool — checked before any backend call.
_REQUIRED_PARAMS: dict[str, list[str]] = {
    "get_account_summary":  ["customer_id"],
    "create_support_ticket": ["customer_id", "subject", "body"],
    "initiate_transfer":    ["customer_id", "to_account", "amount", "approval_token"],
}


class ToolGateway:
    """
    Single entry-point for all LLM tool calls.

    Security model
    --------------
    * The agent never touches credentials or backend sessions.
    * All authorization decisions are made here, in Python, before any
      backend function is invoked.
    * The session_id/approval_token arrive as *structured data*, not as
      text parsed from a prompt.
    """

    def __init__(
        self,
        sessions:     dict[str, dict[str, Any]] | None = None,
        approvals:    dict[str, dict[str, Any]] | None = None,
        metric_store: dict[str, dict[str, int]] | None = None,
    ) -> None:
        """
        Decision 3 (rewrite) — all-or-nothing state injection.

        Pass all three stores together (for unit tests with isolated state),
        or pass none (for normal use with the module-level globals).
        Partial injection raises TypeError immediately so the misconfiguration
        is caught at construction time, not silently at the first tool call.
        """
        provided = [sessions, approvals, metric_store]
        none_count = provided.count(None)
        if none_count not in (0, 3):
            raise TypeError(
                "ToolGateway requires either all state stores or none. "
                f"Got {3 - none_count}/3 stores provided. "
                "Pass sessions=, approvals=, and metric_store= together, "
                "or omit all three to use the module-level defaults."
            )
        self._sessions  = sessions     if sessions     is not None else session_store
        self._approvals = approvals    if approvals    is not None else approval_store
        self._metrics   = metric_store if metric_store is not None else metrics

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute_tool(
        self,
        session_id: str,
        tool_name:  str,
        params:     dict[str, Any],
    ) -> GatewayResult:
        """
        Validate and dispatch a tool call.

        Validation order (fail-fast):
          1. Session lookup
          2. Tool name allow-list
          3. Required parameters present
          4. Identity check  – params['customer_id'] == session['customer_id']
          5. Transfer-specific approval check
          6. Backend dispatch
        """
        tool_name = tool_name.strip()

        # --- step 1: session lookup ----------------------------------------
        session = self._sessions.get(session_id)
        if session is None:
            log.warning("Unknown session_id=%r", session_id)
            return GatewayResult(Status.DENIED, message="Unknown or expired session.")

        authenticated_customer = session["customer_id"]

        # --- step 2: tool allow-list -----------------------------------------
        if tool_name not in _REQUIRED_PARAMS:
            self._inc(tool_name, "denied")
            log.warning(
                "session=%r requested unknown tool=%r", session_id, tool_name
            )
            return GatewayResult(
                Status.DENIED, message=f"Tool '{tool_name}' is not available."
            )

        self._inc(tool_name, "calls")

        # --- step 3: required parameters ------------------------------------
        missing = [k for k in _REQUIRED_PARAMS[tool_name] if k not in params]
        if missing:
            self._inc(tool_name, "errors")
            log.error(
                "tool=%r missing params=%r session=%r", tool_name, missing, session_id
            )
            return GatewayResult(
                Status.ERROR,
                message=f"Missing required parameter(s): {', '.join(missing)}",
            )

        # --- step 4: identity check -----------------------------------------
        requested_customer = params["customer_id"]
        if requested_customer != authenticated_customer:
            self._inc(tool_name, "denied")
            log.warning(
                "IDENTITY MISMATCH  session=%r  auth=%r  requested=%r  tool=%r",
                session_id, authenticated_customer, requested_customer, tool_name,
            )
            return GatewayResult(
                Status.DENIED,
                message=(
                    "Identity mismatch: the requested customer does not match "
                    "the authenticated session."
                ),
            )

        # --- step 5: transfer-specific approval check -----------------------
        if tool_name == "initiate_transfer":
            result = self._validate_transfer_approval(
                authenticated_customer, params
            )
            if result is not None:
                self._inc(tool_name, "denied")
                return result

        # --- step 6: dispatch -----------------------------------------------
        try:
            data = self._dispatch(tool_name, authenticated_customer, params)
        except Exception as exc:
            self._inc(tool_name, "errors")
            log.exception("Backend error  tool=%r  session=%r", tool_name, session_id)
            return GatewayResult(
                Status.ERROR,
                message=f"Backend error: {exc}",
            )

        log.info(
            "OK  session=%r  tool=%r  customer=%r",
            session_id, tool_name, authenticated_customer,
        )
        self._inc(tool_name, "backend_calls")
        return GatewayResult(Status.OK, data=data)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate_transfer_approval(
        self,
        authenticated_customer: str,
        params: dict[str, Any],
    ) -> GatewayResult | None:
        """
        Return a denial GatewayResult if the approval_token is invalid,
        or None if the token is good.

        A valid token must:
          • exist in the approval store
          • not have been used already  (single-use)
          • belong to the authenticated customer
          • match the requested to_account exactly
          • match the requested amount exactly (Decimal comparison)

        Decision 2 (keep) — tokens are consumed BEFORE the backend call.
        If the backend later raises, the token stays consumed. This is the
        safer default: a token that could be un-consumed on failure opens a
        window for an intentional crash-and-retry loop. Failing closed is
        the correct invariant here.
        Live-system note: a production implementation would replace this with
        idempotency keys or a two-phase commit (prepare → confirm) so that a
        genuine network hiccup does not force the customer to re-authorise.
        """
        token = params["approval_token"]
        approval = self._approvals.get(token)

        if approval is None:
            log.warning("Unknown approval_token=%r", token)
            return GatewayResult(
                Status.DENIED, message="Invalid or unknown approval token."
            )

        if approval["used"]:
            log.warning("Replay of used approval_token=%r", token)
            return GatewayResult(
                Status.DENIED,
                message="Approval token has already been used.",
            )

        if approval["customer_id"] != authenticated_customer:
            log.warning(
                "Token owner mismatch  token=%r  token_owner=%r  auth=%r",
                token, approval["customer_id"], authenticated_customer,
            )
            return GatewayResult(
                Status.DENIED,
                message="Approval token does not belong to the authenticated customer.",
            )

        if approval["to_account"] != params["to_account"]:
            log.warning(
                "Token destination mismatch  token=%r  expected=%r  got=%r",
                token, approval["to_account"], params["to_account"],
            )
            return GatewayResult(
                Status.DENIED,
                message="Approval token destination does not match the requested destination.",
            )

        # Decision 1 (rewrite) — use Decimal for exact amount comparison.
        # Accepts int, float, or string from the caller; normalises all three.
        # InvalidOperation is raised by Decimal() on garbage input (e.g. "abc").
        try:
            requested_amount = Decimal(str(params["amount"]))
        except (InvalidOperation, TypeError):
            return GatewayResult(
                Status.ERROR,
                message=(
                    "Parameter 'amount' must be a numeric value "
                    "(e.g. 500, 500.00, or \"500.00\")."
                ),
            )

        if approval["amount"] != requested_amount:
            log.warning(
                "Token amount mismatch  token=%r  expected=%r  got=%r",
                token, approval["amount"], requested_amount,
            )
            return GatewayResult(
                Status.DENIED,
                message="Approval token amount does not match the requested amount.",
            )

        # Mark token consumed (single-use) — see Decision 2 note above.
        approval["used"] = True
        log.info("Approval token consumed  token=%r", token)
        return None   # all checks passed

    def _dispatch(
        self,
        tool_name:  str,
        customer_id: str,
        params:     dict[str, Any],
    ) -> dict[str, Any]:
        """Call the appropriate stub backend function."""
        if tool_name == "get_account_summary":
            return get_account_summary(customer_id)

        if tool_name == "create_support_ticket":
            return create_support_ticket(
                customer_id=customer_id,
                subject=str(params.get("subject", "")),
                body=str(params.get("body", "")),
            )

        if tool_name == "initiate_transfer":
            return initiate_transfer(
                customer_id=customer_id,
                to_account=params["to_account"],
                amount=Decimal(str(params["amount"])),
                approval_token=params["approval_token"],
            )

        raise ValueError(f"No dispatch handler for tool '{tool_name}'.")

    def _inc(self, tool_name: str, counter: str) -> None:
        """Safely increment a metrics counter, even for unknown tool names."""
        bucket = self._metrics.setdefault(
            tool_name, {"calls": 0, "denied": 0, "errors": 0}
        )
        bucket[counter] = bucket.get(counter, 0) + 1


# ---------------------------------------------------------------------------
# 5. QUICK SMOKE-TEST  (python gateway.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    gw = ToolGateway()

    print("\n── Test 1: valid account summary ─────────────────────────────")
    r = gw.execute_tool("sess_alice", "get_account_summary", {"customer_id": "cust_001"})
    print(r)

    print("\n── Test 2: identity mismatch (Alice trying to read Bob) ───────")
    r = gw.execute_tool("sess_alice", "get_account_summary", {"customer_id": "cust_002"})
    print(r)

    print("\n── Test 3: unknown session ─────────────────────────────────────")
    r = gw.execute_tool("sess_hacker", "get_account_summary", {"customer_id": "cust_001"})
    print(r)

    print("\n── Test 4: valid transfer ──────────────────────────────────────")
    r = gw.execute_tool(
        "sess_alice", "initiate_transfer",
        {
            "customer_id":    "cust_001",
            "to_account":     "acc_external_99",
            "amount":         "500.00",          # string — Decimal("500.00") ✓
            "approval_token": "tok_abc123",
        },
    )
    print(r)

    print("\n── Test 5: replay the same token (must be denied) ─────────────")
    r = gw.execute_tool(
        "sess_alice", "initiate_transfer",
        {
            "customer_id":    "cust_001",
            "to_account":     "acc_external_99",
            "amount":         "500.00",
            "approval_token": "tok_abc123",
        },
    )
    print(r)

    print("\n── Test 6: tampered amount ─────────────────────────────────────")
    r = gw.execute_tool(
        "sess_bob", "initiate_transfer",
        {
            "customer_id":    "cust_002",
            "to_account":     "acc_external_77",
            "amount":         999.99,             # float — Decimal("999.99") ≠ Decimal("100.00")
            "approval_token": "tok_def456",
        },
    )
    print(r)

    print("\n── Test 7: missing required param ──────────────────────────────")
    r = gw.execute_tool("sess_bob", "create_support_ticket", {"customer_id": "cust_002"})
    print(r)

    print("\n── Test 8: unknown tool name ───────────────────────────────────")
    r = gw.execute_tool("sess_bob", "drop_database", {"customer_id": "cust_002"})
    print(r)

    print("\n── Test 9: amount as float (500.0) — same value, must match ───")
    # Reset tok_abc123 for this isolated Decimal-flexibility test.
    approval_store["tok_abc123"]["used"] = False
    r = gw.execute_tool(
        "sess_alice", "initiate_transfer",
        {
            "customer_id":    "cust_001",
            "to_account":     "acc_external_99",
            "amount":         500.0,             # float → Decimal("500.0") == Decimal("500.00")
            "approval_token": "tok_abc123",
        },
    )
    print(r)

    print("\n── Test 10: garbage amount string (must error) ─────────────────")
    approval_store["tok_abc123"]["used"] = False
    r = gw.execute_tool(
        "sess_alice", "initiate_transfer",
        {
            "customer_id":    "cust_001",
            "to_account":     "acc_external_99",
            "amount":         "five hundred",
            "approval_token": "tok_abc123",
        },
    )
    print(r)

    print("\n── Metrics ─────────────────────────────────────────────────────")
    for tool, counts in metrics.items():
        print(f"  {tool}: {counts}")
