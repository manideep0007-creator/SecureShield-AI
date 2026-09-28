# V1 BASELINE SNAPSHOT

**Project**: SecureShield AI  
**Version**: 1.0  
**Snapshot Date**: 2026-09-28  
**Status**: Stable — all engines operational, test suite passing

---

## Purpose

This folder is a **read-only reference snapshot** of the SecureShield AI project at the V1 milestone. It records the exact project structure, feature set, API surface, dependency versions, engine configurations, and database schemas as they exist at the time of this baseline.

**No application code lives in this folder.** It is documentation only.

Use this baseline to:
- Compare future revisions against the V1 state
- Verify that refactors preserve V1 functionality
- Onboard new contributors with a known-good reference
- Roll back design decisions by consulting the recorded architecture

---

## Contents

| File | Description |
|---|---|
| `README.md` | This file — baseline overview and purpose |
| `STRUCTURE.md` | Complete project file tree with annotations |
| `FEATURES.md` | All implemented features and their current status |
| `APIS.md` | Full API surface — endpoints, request/response schemas, external integrations |
| `DEPENDENCIES.md` | All backend and Android dependencies with versions |
| `ENGINE_CONFIG.md` | Detection engine parameters, confidence weights, thresholds, and flag definitions |
| `DATABASE_SCHEMAS.md` | SQLite table schemas for sender_behavior.db and feedback.db |

---

## V1 Summary

SecureShield AI V1 is a two-tier mobile security platform:
- **Android client** (Kotlin) — intercepts shared URLs/files via implicit intents, integrates Gmail scanning via OAuth, renders threat verdicts with explainable reasoning and user feedback
- **Python backend** (FastAPI) — runs a modular 4-engine detection pipeline (URL, Malware, NLP, Sender Behavior) aggregated by a fusion engine into scored, categorized, human-readable threat verdicts
