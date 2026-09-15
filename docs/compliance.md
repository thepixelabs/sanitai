# Compliance Reference

Version: v0.1.x  
Last reviewed: 2026-04-10  
Audience: Security engineers, DPOs, and compliance teams evaluating SanitAI in regulated environments.

---

## What SanitAI does and does not do

SanitAI is a local command-line tool that reads LLM export files and reports findings to stdout. It does **not**: store findings, log activity, maintain a database, communicate over a network, or provide centralised visibility, fleet management, policy enforcement, audit logging, or RBAC.

Those capabilities are planned for a paid tier. v0.1 is a developer tool, not a compliance platform.

---

## GDPR — Article 32: Security of processing

### How SanitAI supports Article 32 compliance

**Detection of PII in unstructured conversation data (Art. 32(1)(d))**

Organisations using LLM tools in workflows where personal data may be present can use SanitAI as part of a regular testing process. Running `sanitai scan` against periodic exports provides evidence that PII accumulation in LLM tools is being actively monitored — supporting the "regularly testing and evaluating" obligation.

**Data minimisation support (Art. 5(1)(c))**

`sanitai redact` produces a PII-stripped copy of an export. This supports data minimisation when exports must be retained for other purposes (model fine-tuning review, audit evidence).

**Local processing — no secondary processing risk**

Because SanitAI processes data entirely on the local machine, using it does not constitute a transfer of personal data to a third party and does not create a processor relationship. No Article 28 agreement is required.

### What SanitAI does NOT provide for GDPR

- No Article 30 Record of Processing Activities (ROPA)
- No data retention or deletion enforcement
- No Subject Access Request (SAR) workflow
- No detection of all Article 9 special category data
- No substitute for a DPIA

---

## SOC 2 — Common Criteria mapping

### CC6.1 — Logical and physical access controls

LLM conversation exports containing credentials represent a logical access risk. SanitAI supports CC6.1 evidence by:

- Providing a repeatable, auditable scan for credential exposure
- Enabling developers to detect and redact credentials before exports are shared or archived

**Evidence artefact:** Run `sanitai scan <export>` and retain the output as evidence of the credential scanning control operating.

### CC6.6 — Logical access — external threats

Credentials in LLM histories represent a secret sprawl risk. SanitAI supports CC6.6 by:

- Reducing the blast radius of an export file breach
- Providing a signal for credential rotation workflows: detect → rotate → redact → re-scan

### What SanitAI does NOT provide for SOC 2

- **No audit log.** If CC7.2 requires an audit trail of scanning activity, wrap SanitAI in a script that captures its output.
- **No centralised control.** No management console, policy enforcement, or fleet-wide reporting in v0.1.
- **Not a substitute for secrets management.** SanitAI is a detective control. The primary control is a secrets manager that prevents secrets from entering conversation text in the first place.

---

## Using SanitAI as a compensating control

```
Primary control:    Secrets manager — prevent secrets entering LLM prompts
Detective control:  SanitAI — scan exports for secrets that leaked anyway
Response control:   Rotate any found credentials immediately
Corrective control: Redact the export, update developer guidance
```

---

## Version note

This document describes v0.1.x behaviour. Re-assess mappings after each minor version upgrade.
