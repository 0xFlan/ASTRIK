# Evidence Bar and Reporting

The difference between a professional finding and a guess is a replayable artifact. This file defines the minimum.

## 1. Confidence: two values only

| Value | Meaning | Example |
|---|---|---|
| `observed` | You executed it and saw the result | `curl` returned another user's email |
| `inferred` | You reasoned from evidence but did not trigger it | This version is vulnerable to CVE-X |

No "likely", "probably", or "confirmed-ish". If you did not see it, it is inferred.

## 2. Evidence levels

| Level | What it is | Reportable as |
|---|---|---|
| L1 | Clue: version match, banner, page text, scanner output | Not reportable; record as an inferred fact |
| L2 | Input reaches the sink but no real impact (error, timing, reflection) | Medium at most; state the exploitation condition |
| L3 | Real impact: read another principal's data, read a file, change state | High |
| L4 | Full chain or control: admin, RCE, bulk access, cross-tenant | Critical |

Hard gates for high/critical: at least one mechanical artifact — HTTP status + response body, command + output, JSON field echo, or an out-of-band callback record. A version string, a tool banner, or "the page says admin" never qualifies.

## 3. Confirmation gate

A finding is confirmed only when all three hold:

1. **Real trigger**: the target changed behavior in a way that matters (data returned, state changed, privilege gained).
2. **Replayable artifact**: the exact request/response or command/output is stored in `evidence/`, and another operator can repeat it.
3. **Independent reproduction**: a different entry point, parameter, or session reproduced it.

Access control additionally requires **two principals**. A single account seeing an object is not proof of a boundary failure.

## 4. Fact format

```markdown
- [F012] 2026-11-09 14:32 #intent-03 (api.example.com)
  summary: GET /api/v1/users/{id} returns any user's profile; tested ids 1001-1003 across two accounts
  confidence: observed
  evidence: evidence/ev-012-a3f8c2d1.txt
  tags: idor, authz
```

- Summary states the conclusion, not the process.
- Negative results are facts: "no port other than 80/443 on sub.example.com (full scan, observed)".
- Append; never rewrite history. Attribute each fact to an intent or chain.

## 5. Evidence files

- Name: `ev-NNN-<first8 of sha256>.txt`, written once, never edited.
- Content: timestamp, command, full request, full response (or command + full output).
- Redact secrets in the *report*, not in the evidence file; restrict who can read the evidence directory.
- If output was lost or truncated, re-run. Never reconstruct from memory.

## 6. Finding file

```markdown
# [F-NNN] <asset> — <class> — <one-line impact>

- severity: critical | high | medium | low
- vulnclass: idor | sqli | rce | auth-bypass | info-leak | logic | ...
- asset: https://api.example.com (service #S03 → endpoint #E17)
- status: confirmed
- chain: #C-02 (links 1-4)
- date: 2026-11-09

## Summary
What the asset does, what is wrong, what an attacker gains.

## Impact
Concrete data/actions/scope. Name the amplifier (multi-tenant, admin, persistence, root).

## Affected scope
Exact URLs, parameters, roles, versions.

## Reproduction
Preconditions, then a numbered request sequence with expected output per step.

## Evidence
- ev-012-a3f8c2d1.txt — original request/response
- ev-013-9b1d0e77.txt — independent reproduction

## Chain
Link table (stage, action, artifact, evidence, confidence). Mark any inferred link.

## Root cause
Code or configuration reason, with file:line when source is available.

## Fix
Immediate containment and long-term correction.
```

## 7. Severity

| Severity | Standard |
|---|---|
| Critical | System control, RCE, full auth bypass, entire core datastore, cross-tenant admin |
| High | Large sensitive-data exposure, arbitrary file read/write, privilege escalation to admin, stored XSS against admins |
| Medium | Conditional impact: reflected XSS, limited IDOR, narrow logic flaw, SSRF without metadata access |
| Low | Information disclosure, weak configuration, theoretical with a high bar |

When unsure, choose the lower severity and explain why. A chain is capped by its weakest proven link; if an inferred link is essential, report it as partial, not critical.

## 8. Reporting discipline

- Every sentence is backed by evidence. If you cannot point to a file, delete the sentence.
- Write the root cause and fix for the developer, not for an executive.
- Include the baseline (what a normal user sees) next to the exploit result; differentials are the proof.
- For a chain, include the diagram and the link table. Reviewers must see which link is proven and which is hypothesized.
- Keep the report reproducible after the engagement: no dependency on a session that will expire, or note the expiry.

## 9. Retest

- New conclusion, new file; never rewrite the original finding.
- Outcomes: `reproduced`, `fixed`, `inconclusive`. An environment change that prevents reproduction is `inconclusive`, not `fixed`.
- A fix is confirmed only when the original evidence path now fails while the legitimate baseline still works.

## 10. Final self-check

```
[ ] Every fact has confidence + evidence pointer
[ ] Every confirmed finding has an independent reproduction
[ ] Every authz finding has two principals
[ ] Every chain link has an artifact and a status
[ ] No L1 clue is written as a confirmed vulnerability
[ ] Out-of-scope discoveries are logged, not tested
[ ] Test data and changed state are cleaned up
[ ] Credentials that touched the lab are flagged for rotation
```
