# LLM Tool Gateway — Digital Bank Take-Home Exercise

A Python implementation of a **security-first tool gateway** that sits between
an LLM support agent and a stubbed banking backend. All authorization is
decided mechanically, in code. Prompt wording is never a security control.

> **Disclaimer:** Exercise only. No real bank, no real credentials, no real
> money. All state lives in in-process Python dicts.

```
python3 -m pytest test_gateway.py -v   # 24 invariant tests
python3 attack_eval.py                 # 3-attack scripted eval, exits 1 on breach
python3 gateway.py                     # 10 smoke tests
```

---

## 1. Trust Boundaries

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │  UNTRUSTED ZONE                                                      │
 │                                                                      │
 │  [Customer / User]                                                   │
 │       │  types a message in a chat UI                                │
 │       ▼                                                              │
 │  [LLM Agent]  ◄─── UNTRUSTED: model output is attacker-controlled   │
 │       │  calls execute_tool(session_id, tool_name, params)           │
 │       │  ◄─── UNTRUSTED: tool results fed back to model are          │
 │       │        also attacker-controllable (prompt injection surface)  │
 │       │                                                              │
 └───────┼──────────────────────────────────────────────────────────────┘
         │  structured params only — no raw text evaluated
         ▼
 ════════════════════════════  TRUST BOUNDARY  ════════════════════════
         │  Identity source: session_store (operator-seeded at login)
         │  Token source:    approval_store (operator-seeded out-of-band)
         ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  TRUSTED ZONE                                                        │
 │                                                                      │
 │  [ToolGateway]                                                       │
 │       │  enforces: session auth, identity isolation,                 │
 │       │            allow-list, required params, token validation      │
 │       │  only if ALL checks pass:                                    │
 │       ▼                                                              │
 │  [Backend Stubs]  — get_account_summary                             │
 │                   — create_support_ticket                            │
 │                   — initiate_transfer                                │
 └──────────────────────────────────────────────────────────────────────┘
```

**Where identity comes from at each hop**

| Hop | Identity source | Trusted? |
|-----|----------------|----------|
| Customer → Agent | Browser session / auth cookie (outside scope) | Assumed valid |
| Agent → Gateway | `session_id` token passed as structured param | **Not trusted** — gateway looks it up |
| Gateway → `session_store` | Operator-seeded dict keyed by `session_id` | **Trusted** — set at login, never by agent |
| Gateway → Backend | `customer_id` taken from `session_store`, not from agent params | **Trusted** |

The agent never supplies a customer identity that the gateway believes. It
supplies only a `session_id`; the gateway resolves the customer from its own
state.

---

## 2. Permission Model

Three principals are involved in every tool call:

| Principal | Role | What they control |
|-----------|------|-------------------|
| **Operator** | The bank | Seeds `session_store` at login; pre-issues approval tokens in `approval_store` out-of-band (e.g. via a human-confirmation step) |
| **Customer** | The authenticated end-user | Owns a session; can only act on their own data |
| **Agent** | The LLM | Calls tools with structured params; has no credential, no token, no identity of its own |

**How one call's permission is decided:**

```
1. Is session_id in operator-seeded session_store?          → identity resolved
2. Is tool_name in operator-defined allow-list?             → scope enforced
3. Does params["customer_id"] == session["customer_id"]?    → customer boundary enforced
4. For transfers: does approval_token match operator-issued
   token (customer, destination, amount, single-use)?       → money-movement authorised
```

The agent can *request* any of the above, but cannot *grant* itself any of
them. All grants live in operator-controlled state that the agent cannot write.

---

## 3. Failure Table

| # | Attack | Control | Where enforced | Test name |
|---|--------|---------|----------------|-----------|
| 1 | Cross-customer data read (Alice reads Bob's balance) | `params["customer_id"] == session["customer_id"]` | `gateway.py` step 4 — `execute_tool` | `TestIdentityIsolation::test_cross_customer_read_is_denied` |
| 2 | Prompt injection in tool result → unauthorized transfer | Approval token must exist in `approval_store` (operator-seeded); fabricated token strings are rejected | `gateway.py` step 5 — `_validate_transfer_approval` | `TestApprovalTokenValidation::test_unknown_token_is_denied` / `attack_eval.py::Attack A` |
| 3 | Approval token replay (reuse a consumed token) | `approval["used"] == True` check; token marked consumed before backend call | `gateway.py` `_validate_transfer_approval` | `TestApprovalTokenValidation::test_replayed_token_is_denied` |
| 4 | Transfer amount tamper (token says £300, request says £9,999) | `Decimal` exact match: `approval["amount"] != Decimal(str(params["amount"]))` | `gateway.py` `_validate_transfer_approval` | `TestApprovalTokenValidation::test_amount_tamper_is_denied` / `attack_eval.py::Attack C` |
| 5 | Transfer destination tamper (redirect to attacker account) | Exact string match: `approval["to_account"] != params["to_account"]` | `gateway.py` `_validate_transfer_approval` | `TestApprovalTokenValidation::test_destination_tamper_is_denied` |
| 6 | Unknown / invented tool name (e.g. `drop_database`) | Tool allow-list (`_REQUIRED_PARAMS` dict); anything not in it is denied before any other check | `gateway.py` step 2 — `execute_tool` | `TestToolAllowList::test_unknown_tool_is_denied` |

---

## 4. Decision Log

**How I started**

Wrote the security model on paper first (the five validation steps, the three
principals, what the trust boundary means) before writing a single line of
Python. The code followed the model, not the other way around. No existing
codebase was used as a starting point.

**What I rejected**

- **Policy language (e.g. YAML rules, Rego).** The permissions are simple
  enough to express directly in Python. A policy language adds a parser,
  an evaluator, and a new attack surface for injection — all cost, no benefit
  at this scale.

- **Middleware / decorator pattern for the validation pipeline.** An
  `@require_session`, `@require_identity` decorator chain looks elegant but
  obscures the execution order. A single `execute_tool` method with six numbered
  steps is auditable in one read.

- **`async` / `await`.** The stubs are synchronous. Adding async machinery
  for a stub exercise is noise that makes the security logic harder to follow.

- **A separate `rules.py` module.** The gateway's rules *are* its code. Splitting
  them out would create a false sense that the gateway is "configurable" and
  invite the kind of prompt-driven rule-change that this design is built to prevent.

**What I cut (and why)**

- **Session TTL / expiry.** A real gateway would reject sessions older than N
  minutes. Cut because the stub's `session_store` has no clock; adding fake
  timestamps would obscure the actual security invariants being demonstrated.

- **Rate limiting.** Important in production to prevent brute-force token
  guessing. Cut for the same reason: it's operational hardening, not a trust-boundary control, and would add noise here.

- **Audit log persistence.** The gateway logs every decision to stdout via the
  `logging` module. A production system would write to an append-only audit
  store. Cut because the exercise asks for stubs, not infrastructure.

- **Operator API for seeding sessions/tokens.** In a real system the
  `session_store` and `approval_store` are written by authenticated operator
  services, not hardcoded dicts. The hardcoded dicts are the stub equivalent;
  adding an operator API would be building a bank.

---

## 5. AI Review Log

**Tool used:** Gemini (Antigravity, Claude Sonnet 4.6 Thinking model)

**What the AI drafted:**
The AI wrote the initial `gateway.py` from scratch: the mock state dicts,
the three stub backend functions, the `ToolGateway` class with the five-step
validation pipeline, the `GatewayResult` dataclass, and the first 10 smoke
tests in `__main__`. It also drafted the first version of this README and the
`test_gateway.py` / `attack_eval.py` files.

**Two things I threw away or rewrote (and why):**

**1 — Integer cents → `decimal.Decimal` (rewritten)**

The AI's first draft stored amounts as `int` cents (`50_000` for £500.00) and
compared with `int(params["amount"])`. I rejected this because:

- The cents convention is invisible to callers — a `50` vs `50_000` mistake is
  a silent semantic error that passes all type checks.
- `int()` truncates floats silently (`int(499.99)` → `499`), which is
  dangerous for financial comparisons.
- The stub data (`50_000`) looks nothing like a real amount, making the data
  harder to audit at a glance.

Rewritten to `Decimal("500.00")` stored in `approval_store`, with
`Decimal(str(params["amount"]))` for normalisation. Exact comparison, no
rounding, human-readable values, `InvalidOperation` caught and surfaced as
`Status.ERROR`.

**2 — Partial state injection → all-or-nothing (rewritten)**

The AI's first `__init__` accepted three optional kwargs and silently fell back
to module-level globals for any that were `None`. This allowed a caller to
inject `sessions` while letting `approvals` fall through to the shared global
dict — causing cross-test state contamination with no error message.

Rewritten to: if any of the three stores is provided, all three must be
provided, or `TypeError` is raised immediately at construction. The all-or-
nothing rule makes the contract unambiguous and surfaces misconfiguration at
the earliest possible moment.

---

## Files

| File | Purpose |
|------|---------|
| `gateway.py` | Gateway implementation + 10 smoke tests (`python3 gateway.py`) |
| `test_gateway.py` | 24 pytest invariant tests — one per security property |
| `attack_eval.py` | 3-attack scripted eval, exits 1 on breach |
| `README.md` | This file |

**Requirements:** Python 3.10+, `pytest` (tests only). No third-party packages
for `gateway.py` or `attack_eval.py`.
