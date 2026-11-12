# LLM Tool Gateway — Digital Bank Take-Home Exercise

A Python implementation of a **security-first tool gateway** that sits between
an LLM agent and a (stubbed) banking backend. The gateway enforces every
authorization decision mechanically, in code — prompt wording is never a
security control.

> **Disclaimer:** This is a take-home exercise. No real bank, no real
> credentials, no real money. All state lives in in-process Python dicts.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Safety Properties](#safety-properties)
4. [Mock State](#mock-state)
5. [Backend Tools (Stubbed)](#backend-tools-stubbed)
6. [Gateway Class](#gateway-class)
7. [Running the Code](#running-the-code)
8. [AI Review Log](#ai-review-log)

---

## Overview

```
LLM Agent
    │  tool_name, params (structured JSON)
    ▼
┌─────────────────────────────────────────┐
│            ToolGateway                  │
│  1. Session lookup                      │
│  2. Tool allow-list                     │
│  3. Required-param check                │
│  4. Identity isolation                  │
│  5. Approval-token validation (xfers)   │
│  6. Backend dispatch                    │
└─────────────────────────────────────────┘
    │  GatewayResult(status, data, message)
    ▼
Stubbed Backend (get_account_summary /
                 create_support_ticket /
                 initiate_transfer)
```

The agent **never** holds a session credential, an approval token, or any
backend secret. It calls `execute_tool(session_id, tool_name, params)` and
receives a structured result. All trust decisions happen inside the gateway.

---

## Architecture

| Layer | Responsibility |
|-------|---------------|
| **Mock State** | `session_store`, `approval_store`, `metrics` — in-process dicts |
| **Backend Stubs** | Three pure functions; called only after all checks pass |
| **ToolGateway** | Fail-fast validation pipeline; single public method `execute_tool` |
| **GatewayResult** | Typed response — `Status.OK / DENIED / ERROR` + data + message |

### Validation order (fail-fast)

```
session_id known?           → DENIED  (unknown/expired session)
tool_name in allow-list?    → DENIED  (tool not available)
all required params present?→ ERROR   (missing params)
customer_id == session owner?→ DENIED (identity mismatch)
[transfer only] token valid? → DENIED (bad/used/tampered token)
backend call                → OK / ERROR (backend exception)
```

Every check that fails returns immediately — later checks never run.

---

## Safety Properties

### 1 — Identity Isolation

A session can only read or act on the customer it was authenticated as.
The gateway compares `params["customer_id"]` against `session["customer_id"]`
from the session store. An LLM that generates a different customer ID in its
tool call is blocked unconditionally.

```python
# DENIED — Alice's session cannot read Bob's account
gw.execute_tool("sess_alice", "get_account_summary", {"customer_id": "cust_002"})
```

### 2 — Transfer Authorization via Approval Tokens

Every `initiate_transfer` call must supply an `approval_token` that was
pre-issued out-of-band (e.g. by a human-in-the-loop step). The token is
validated on five dimensions simultaneously:

| Check | What is compared |
|-------|-----------------|
| Existence | token must be in `approval_store` |
| Single-use | token must not already be `used=True` |
| Owner | token's `customer_id` == session's `customer_id` |
| Destination | token's `to_account` == `params["to_account"]` |
| Amount | token's `amount` == `Decimal(str(params["amount"]))` |

A tampered amount, a replayed token, or a token belonging to another customer
all result in `Status.DENIED`.

### 3 — Prompt-Agnostic Enforcement

No part of the gateway reads, parses, or evaluates prompt text. All inputs
arrive as typed Python values (`str`, `Decimal`, `dict`). An injection attempt
embedded in a prompt string cannot change the control flow.

---

## Mock State

```python
session_store   # session_id  → {customer_id, created_at}
approval_store  # token       → {customer_id, to_account, amount (Decimal), used}
metrics         # tool_name   → {calls, denied, errors}

_accounts       # customer_id → list of account dicts  (private, read by stubs)
```

Seeded with two customers (`cust_001` / `cust_002`), two sessions
(`sess_alice` / `sess_bob`), and two pre-issued approval tokens.

---

## Backend Tools (Stubbed)

| Function | Inputs | Returns |
|----------|--------|---------|
| `get_account_summary(customer_id)` | customer ID | accounts list + total balance |
| `create_support_ticket(customer_id, subject, body)` | ticket fields | ticket ID + status |
| `initiate_transfer(customer_id, to_account, amount, approval_token)` | transfer fields | transfer ID + status |

Backend stubs are **plain functions** — they perform no authorization. All
authorization is complete before they are called.

---

## Gateway Class

```python
gw = ToolGateway()                          # use module-level state
gw = ToolGateway(sessions, approvals, metrics)  # inject all three for tests
```

> **All-or-nothing injection:** pass all three stores or none. Partial
> injection raises `TypeError` at construction time so misconfiguration is
> caught immediately, not silently at the first tool call.

### `execute_tool(session_id, tool_name, params) → GatewayResult`

```python
result = gw.execute_tool(
    "sess_alice",
    "initiate_transfer",
    {
        "customer_id":    "cust_001",
        "to_account":     "acc_external_99",
        "amount":         "500.00",    # int, float, or str — all accepted
        "approval_token": "tok_abc123",
    },
)

result.status   # Status.OK | Status.DENIED | Status.ERROR
result.data     # dict with backend response (empty on failure)
result.message  # human-readable reason on failure
```

---

## Running the Code

**Requirements:** Python 3.10+ (uses `X | Y` union type hints), no third-party
packages.

```bash
python3 gateway.py
```

The `__main__` block runs 10 smoke tests covering every acceptance criterion:

| Test | Scenario | Expected |
|------|----------|----------|
| 1 | Valid account summary | `OK` |
| 2 | Alice reads Bob's account | `DENIED` — identity mismatch |
| 3 | Unknown session | `DENIED` |
| 4 | Valid transfer (`"500.00"` string) | `OK` |
| 5 | Replay same token | `DENIED` — already used |
| 6 | Tampered amount (`999.99` vs `100.00`) | `DENIED` |
| 7 | Missing required params | `ERROR` |
| 8 | Unknown tool name | `DENIED` |
| 9 | Amount as float `500.0` (Decimal flex) | `OK` |
| 10 | Garbage amount string `"five hundred"` | `ERROR` |

---

## AI Review Log

This section documents three design decisions reviewed interactively with the
AI pair-programmer during development. Each decision was discussed, voted on
(keep / reject / rewrite), and updated before the final commit.

---

### Decision 1 — Amount representation

**Original:** Amounts stored as `int` cents (e.g. `50_000` for £500.00).

**Concern raised:** Callers must know the cents convention; a `50` vs `50_000`
mistake is a silent semantic error. The cents label adds no type safety.

**Verdict: ✏️ Rewritten**

**New approach:** Amounts stored as `decimal.Decimal` in natural currency units
(`Decimal("500.00")`). The gateway normalises caller input via
`Decimal(str(params["amount"]))`, accepting `int`, `float`, or `str`
transparently. `decimal.InvalidOperation` is caught and returned as
`Status.ERROR` with a clear message.

**Why this is safer:**
- `Decimal` comparison is exact — no floating-point rounding bugs.
- Human-readable values in the stub data (`500.00` not `50000`) make
  accidental scale errors visible at a glance.
- A float like `500.0` and a string `"500.00"` both compare equal to the
  stored `Decimal("500.00")`, so the gateway is flexible without being loose.

---

### Decision 2 — Approval token consumed before backend call

**Original approach (kept):** Inside `_validate_transfer_approval`, once all
five checks pass, `approval["used"] = True` is set **before** `_dispatch` is
called. If the backend later raises an exception, the token stays consumed.

**Verdict: ✅ Kept**

**Rationale:** Failing closed is the correct default for a security gateway.
A token that could be un-consumed on failure opens a window for an intentional
crash-and-retry loop to drain funds. The safer invariant is: once approved,
always consumed.

**Live-system note documented in code:** A production implementation would
replace this pattern with **idempotency keys** or a **two-phase commit**
(prepare → confirm) so that a genuine network hiccup does not force the
customer to re-authorise. That complexity is out of scope for this stub.

---

### Decision 3 — State injection via constructor

**Original:** `ToolGateway.__init__` accepted three optional kwargs, falling
back to module-level globals when any was `None`. This allowed partial
injection — e.g. injecting `sessions` while letting `approvals` fall through
to the shared global — which could cause subtle cross-test contamination.

**Verdict: ✏️ Rewritten**

**New approach:** All-or-nothing injection. If any of the three stores is
provided, all three must be provided. Partial injection raises `TypeError`
at construction time:

```python
# ✅ OK — use module defaults
gw = ToolGateway()

# ✅ OK — fully isolated (e.g. in a unit test)
gw = ToolGateway(sessions={...}, approvals={...}, metric_store={...})

# ❌ TypeError raised immediately at __init__
gw = ToolGateway(sessions={...})   # forgot approvals and metric_store
```

**Why this is safer:** Misconfiguration is caught at object construction, not
silently during the first tool call when the contaminated global state is
already in use. The all-or-nothing rule makes the contract unambiguous.
