# Extracted Tech Summary – MCISE OS

Extraction location: `/Users/mac/Desktop/KasbahFinal/extracted`
Sources:
- `/Users/mac/Downloads/workspace-ac3c7d84-55ed-4559-8ff6-0ad001e1276a.tar`
- `/Users/mac/Downloads/workspace-ac3c7d84-55ed-4559-8ff6-0ad001e1276a (1).tar`
- `/Users/mac/Downloads/workspace-ac3c7d84-55ed-4559-8ff6-0ad001e1276a (2).tar`
- `/Users/mac/Downloads/workspace-ac3c7d84-55ed-4559-8ff6-0ad001e1276a (3).tar`
- `/Users/mac/Downloads/chat-export-1773200262673.json`

## Stack
- Next.js 16.1.1 App Router + React 19
- TypeScript 5 + TailwindCSS 4 + shadcn/ui + Radix UI
- Prisma 6.11.1 SQLite/Postgres + Zod validation
- NextAuth-style JWT HS256 + RBAC + MFA TOTP RFC6238
- z-ai-web-dev-sdk model gateway with Fixed Core stripping
- Server-Sent Events for live agent stream
- Docker + Caddy TLS

## Core Architecture Patterns

### 1. Agentic OS with Adversarial Pairs
- 12 agents across 6 adversarial pairs A01-A12
- Agent lifecycle: perceive → reason → act
- Adversarial pairing: primary + adversary runs per event, produces `AgentPairResolution`
- Autonomy Ladder: promotion/demotion rules with accuracy thresholds and tenure
- Evaluation Harness: gold-standard datasets, accuracy + coverage scoring

### 2. Cryptographic Audit & Transparency
- HMAC-SHA256 chained audit log, `src/lib/services/audit.ts`
  - `appendAudit`, `verifyAuditChain`, `listAuditEntries`
- HMAC-signed Fixed Core, `src/lib/services/fixed-core.ts`
  - Vision, Mission, 10 Strategic Refusals, Evidence Hierarchy, Paradox Watch
- W3C Verifiable Credentials issuance/verification
- Kasbah Score 0-100 transparent algorithm
- Right-to-Explanation public endpoint `/api/explain/[id]`
- SIEM export NDJSON, Witness checkpoint co-sign

### 3. RBAC + Security
- Real HS256 JWT, MFA two-step login, session revocation table
- Permission model: 22+ permissions, 8 roles
- Rate limiting per user+endpoint, DB-backed
- Crypto keys auto-generated, production refuses defaults
- Voice command sanitization, SSE auth via query param

### 4. Domain-rich API surface
`/src/app/api` contains 100+ routes across:
- Agents: trigger, kill, stream SSE, SBOM
- Audit: chain, verify
- CRM: persons, organizations, relationships, engagements
- ERP: journal entries, invoices AP/AR, cash, budget, assets with depreciation
- HR: employees, leave, payroll, contracts, performance
- Governance: board packs, decisions, elections, risks, strategy
- Compliance: consent, DSR export, whistleblower, policy-acks
- Documents: upload with VLM auto-extraction, SHA-256 integrity
- OCR / VLM evidence photo analysis
- TTS / ASR voice commands + intent parsing
- Image generation visual briefing
- Ventures / Milestones / Impact Claims with event-driven chaining A11/A12
- SIEM, Witness, VC issue/verify

### 5. Premium AI Features
- OCR intake → VLM extracts structured data → pre-fill forms
- TTS read-aloud for public feed
- ASR voice commands: "kill A01", "verify chain", "approve first escalation"
- Image generation for fleet state visual briefing
- VLM evidence photo analysis for research lead

### 6. Role-routed Workspaces
8 workspaces:
- Director/CEO: critical escalations, kill switches, audit verify, compliance panel
- Finance/CFO: grant escalations, ERP modules
- Programs Director: venture pipeline, impact claims
- Research Lead: evidence tier escalations
- Integrity: paradox watch
- Ethics: Fixed Core modify gated by board token
- Field Staff: CRM person/org entry, OCR intake, consent + documents
- Council: public activity feed observer only

### 7. Production Hardening
- Dockerfile multi-stage, docker-compose with Postgres + Caddy
- Health check `/api/health`
- Configurable storage local/S3
- 23 passing tests: audit, RBAC, MFA, VC
- Build compiles clean

## Files of Immediate Value for Groundbreak

- `src/lib/services/audit.ts` – chained HMAC audit
- `src/lib/services/fixed-core.ts` – HMAC-signed constitutional core
- `src/lib/agents/base.ts` + `specs.ts` + `runtime.ts` – agent system
- `src/lib/agents/ladder.ts` + `harness.ts` – autonomous governance loop
- `src/lib/auth.ts` – JWT + RBAC + MFA
- `prisma/schema.prisma` – full data model
- `src/app/api/agents/*` – agent trigger/stream/kill
- `src/app/api/vc/*`, `src/app/api/explain/*`, `src/app/api/score` – compliance stack
- `worklog.md` – complete development history and design decisions

## Chat Export
`chat-export-1773200262673.json` – 102 MB export of prior development conversation, usable for context retrieval / RAG training.

## Next Steps
- Review `worklog.md` for design rationale
- Import `prisma/schema.prisma` into your own DB
- Reuse agent base class and audit chain as reference implementation for Groundbreak model governance
- Adapt RBAC, MFA, VC issuance patterns for your compliance layer
