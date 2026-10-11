# Competitive Research Findings — AI Security / LLM Security (2026)

Research method: Browser Use (IAB), Bing SERP + primary product pages. Date: 2026-10-01.

## Category 1: LLM Prompt-Injection & Content Safety

### Lakera (Check Point)
- **URL**: https://www.lakera.ai/
- **Category**: LLM prompt-injection / content safety / AI agent security / AI red teaming
- **Core claims**: "Leading security platform to secure your AI future"; real-time threat detection, prompt attack prevention, data leakage protection; workforce AI security (shadow AI discovery); AI red teaming
- **Pre-execution blocking vs post-hoc**: Pre-execution / runtime blocking (sub-50 ms latency claims; "Prevent prompt injections... before they impact")
- **Local-first vs cloud**: Cloud SaaS (platform.lakera.ai); enterprise cloud API
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Enterprise (Fortune 500, Dropbox, AWS, Asana, banks)
- **Pricing**: "Start for free" + Talk to Sales (enterprise sales-led)
- **Differentiators**: 1M+ hacker community learning; 100+ languages; context-aware precision; central policy control without code changes; multimodal + model agnostic; Check Point acquisition (©1994-2026 Check Point Software Technologies Ltd.)
- **Evidence date**: 2026-10-01

### Protect AI → Palo Alto Networks Prisma AIRS
- **URL**: https://protectai.com/ (redirects to Palo Alto Networks Prisma AIRS)
- **Category**: End-to-end AI security platform (gateway + runtime + model + posture + red team)
- **Core claims**: "End-to-end security across the AI lifecycle"; Discover shadow AI, Assess risks, Protect against threats; blocks prompt injections and data leaks
- **Pre-execution blocking vs post-hoc**: Both — pre-execution runtime blocking ("Enforce real-time safeguards") + AI Red Teaming (proactive)
- **Local-first vs cloud**: Cloud (Managed AI Runtime Security for AWS; enterprise SaaS)
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Enterprise
- **Pricing**: Sales-led (Request a Demo)
- **Differentiators**: Acquired Protect AI (LLM Guard heritage); Prisma AIRS = AI Gateway ("AI Control Plane"), Agent Security (agent identity verification), AI Model Security (model tampering/deserialization scanning), AI Posture Management (Cortex), Managed AI Runtime Security for AWS; Gartner "Company to Beat" in AI Security Platforms (June 2026); Microperimeter (NGFW traffic redirect); OAuth2.0 token refresh for agents
- **Market note**: MAJOR CONSOLIDATION — Protect AI is no longer independent as of 2026
- **Evidence date**: 2026-10-01

### HiddenLayer
- **URL**: https://www.hiddenlayer.com/
- **Category**: AI security platform (discovery, supply chain, attack simulation, runtime, guardrails)
- **Core claims**: "Most comprehensive security platform for AI"; patented technology + adversarial AI research; AI Discovery, AI Supply Chain Security, AI Attack Simulation, AI Runtime Security
- **Pre-execution blocking vs post-hoc**: Both — AI Guardrails (prevention) + Attack Simulation / Model Scanning (proactive/posture)
- **Local-first vs cloud**: Cloud platform; AIDR is "non-invasive" and does not need access to customer's sensitive data or proprietary models (privacy-preserving design)
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Enterprise (NFL, GitLab, financial services, US Federal)
- **Pricing**: Sales-led (Book a demo)
- **Differentiators**: $100M Series B (2025/26); patented AIDR runtime defense without model/data access; AI Supply Chain Security + model scanning; Agentic & MCP Protection; US Federal mission assurance; 10+ CVEs disclosed; native CI/CD, MLOps, SIEM/SOAR integrations
- **Evidence date**: 2026-10-01

### CalypsoAI / Robust Intelligence → F5 AI Guardrails
- **URL**: https://www.calypsoai.com/ (redirects to F5 AI Guardrails) | https://www.f5.com/
- **Category**: LLM firewall / AI guardrails / runtime AI security
- **Core claims**: "Define and deploy agile data security, threat management, and governance for AI models, apps, and agents"; combat adversarial attacks; secure AI data; govern responsible AI usage; simplify AI observability
- **Pre-execution blocking vs post-hoc**: Pre-execution blocking (prompt injection defense, block unauthorized tool calls) + post-hoc audit/traceability
- **Local-first vs cloud**: Hybrid — public cloud (AWS/Azure/GCP), private cloud, **on-prem and fully air-gapped** ("Private AI: Maintain consistent privacy with full functionality in on-prem and fully air-gapped deployments")
- **Crypto receipts/proofs**: Not mentioned (audit-ready logging/traceability is standard SIEM-style)
- **Consumer vs enterprise**: Enterprise
- **Pricing**: Sales-led
- **Differentiators**: Combined Robust Intelligence + CalypsoAI under F5; threat library 10,000+ attack patterns/month; CASI Model Risk Leaderboard; natural-language custom policy creation; day-1 compliance (PII, EU AI Act, PCI, PHI); agent tool-call auditing/blocking; **air-gapped deployment is rare vs cloud-only peers**; Gartner Market Shaper 2026 AI Application Security; KuppingerCole GenAI Defense leader; SecureIQLab efficacy validation
- **Market note**: MAJOR CONSOLIDATION — CalypsoAI and Robust Intelligence absorbed into F5
- **Evidence date**: 2026-10-01

### Prompt Security → SentinelOne
- **URL**: https://www.promptsecurity.com/ (domain for sale on GoDaddy as of 2026-10-01)
- **Category**: LLM prompt-injection / GenAI security (historical)
- **Status**: Acquired by SentinelOne; standalone product effectively shut down; domain listed for sale
- **Evidence**: tooldirectory.ai (Jun 26, 2026): "Prompt Security was acquired by SentinelOne and the standalone [product discontinued]"; techshowlondon.co.uk press release on SentinelOne acquisition
- **Market note**: THIRD major consolidation in category 1 (after Protect AI→Palo Alto, CalypsoAI/Robust→F5, Lakera→Check Point)

### Arthur AI
- **URL**: https://www.arthur.ai/
- **Category**: Enterprise agent security & governance / observability / runtime security
- **Core claims**: "Secure and Govern Every Agent"; agent discovery (shadow agents on endpoints/cloud/on-prem); runtime security with guardrails + anomaly alerting; full audit logs and lineage
- **Pre-execution blocking vs post-hoc**: Both — runtime guardrails (prompt injection blocked) + Agent Behavioral Analytics (ABA) anomaly detection + continuous evals
- **Local-first vs cloud**: Cloud SaaS; discovers agents across endpoints, cloud, private data centers
- **Crypto receipts/proofs**: Not mentioned (audit logs/lineage for "prove control" is enterprise audit, not cryptographic receipts)
- **Consumer vs enterprise**: Enterprise (Fortune 500, Axios, Philadelphia Inquirer, Expel)
- **Pricing**: Sales-led (Talk to an AI Expert)
- **Differentiators**: **AGENT COST GOVERNANCE (rare)** — "Token costs, back under control. Track spending by team and user. Requests that don't need the expensive model are automatically detected and rerouted, including to internally-hosted open-source models" (claim: 62% rerouted, 38% spend reduction); Agent Behavioral Analytics; shadow agent discovery; step-level traces of reasoning/tools/retrieval; SOC integrations (CrowdStrike, Splunk, Datadog, Elastic); FISMA/EU AI Act alignment content
- **Evidence date**: 2026-10-01

### Lasso Security
- **URL**: https://www.lasso.security/
- **Category**: AI agent security platform (discovery, posture, red teaming, runtime enforcement, detection & response)
- **Core claims**: "Secure AI Agents at Enterprise Scale"; Discover. Assess. Protect.; AI-BOM; runtime enforcement at proxy/API/AI Gateway
- **Pre-execution blocking vs post-hoc**: Both — inline pre-execution enforcement ("Enforce policies inline at the proxy, API, or AI Gateway layer"; "Zero-latency decision making") + Detection & Response (post-hoc)
- **Local-first vs cloud**: Cloud SaaS; notable: **CPU-based Guardrails** announcement (cost/efficiency-oriented, potentially local compute)
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Enterprise (US DHS, Fiverr, eToro, Kaltura)
- **Pricing**: Sales-led; claims "570x more cost-effective than cloud-native guardrails"
- **Differentiators**: 3 patents-pending; 98.6% detection accuracy; <50ms classification; 3,000+ attack library (OWASP Top 10+); multi-turn agentic attacks; context poisoning & tool-chain manipulation testing; adversarial recon before dynamic attacks; AI-BOM inventory; Latio 2026 AI Security Market Report Leader; Gartner Cool Vendor 2024 / Hype Cycle AI 2026
- **Evidence date**: 2026-10-01

### Pillar Security
- **URL**: https://www.pillar.security/
- **Category**: Agentic AI security platform (discovery, posture, red teaming, runtime guardrails, governance)
- **Core claims**: "Securing the Agentic Workforce"; one platform to discover, test, secure and govern every AI agent
- **Pre-execution blocking vs post-hoc**: Both — Runtime Guardrails ("Threats blocked in runtime") + Red Teaming / posture assessment
- **Local-first vs cloud**: Cloud SaaS
- **Crypto receipts/proofs**: Not mentioned (audit-ready compliance evidence)
- **Consumer vs enterprise**: Enterprise
- **Pricing**: Sales-led (Get a demo)
- **Differentiators**: Gartner Cool Vendor 2026 AI Software Security; Gartner Emerging Market Quadrant AI Pioneer 2026; OWASP Agentic AI Security Landscape (8/9 categories); CRN 10 Hottest AI Security Startups 2026; SAIL 2.0 Framework; MCP & Tool Security / skill poisoning / marketplace coverage; agentic endpoint focus; military-intelligence research team; notable research (sandbox escapes, Grafana MCP session spoofing/SSRF, Unsloth model inspection ACE)
- **Evidence date**: 2026-10-01

### Nightfall AI
- **URL**: https://www.nightfall.ai/
- **Category**: AI-native DLP / data exfiltration prevention / AI agent data security (covers "Enterprise DLP for ChatGPT/Copilot")
- **Core claims**: "AI Moves Your Data. Nightfall Controls It."; real-time visibility and control over sensitive data movement across AI agents, MCP servers, endpoints, SaaS
- **Pre-execution blocking vs post-hoc**: Both — pre-execution blocking (Shadow AI prompt blocked; hooks intercept and block before execution) + real-time scanning / automated remediation
- **Local-first vs cloud**: Cloud SaaS with endpoint hooks (MCP servers discovered running locally on endpoints)
- **Crypto receipts/proofs**: Not mentioned (data lineage reconstruction is forensic, not cryptographic)
- **Consumer vs enterprise**: Enterprise (Snyk, Bitso, Telnyx, Unit21, Nova Credit)
- **Pricing**: Sales-led (Request demo)
- **Differentiators**: AI-native DLP vs legacy DLP; Claude Compliance API integration; hooks-level agent interception (block tool-call exfil); MCP server inventory/blocking; tool call governance (classify PII in agent responses); data lineage across SaaS/endpoint; employee coaching workflow; 10% of Forbes Top 50 AI Companies as customers
- **Evidence date**: 2026-10-01

### Prompt Armor
- **URL**: https://www.promptarmor.com/
- **Category**: AI third-party risk intelligence / agent supply chain risk (TPRM-focused, NOT primarily a runtime firewall)
- **Core claims**: "Continuous Risk Intelligence for the Agent Supply Chain"; assess new AI assets faster, monitor changes
- **Pre-execution blocking vs post-hoc**: Mostly post-hoc / assessment / monitoring — not an inline runtime blocker; interoperable with existing discovery/enforcement tools
- **Local-first vs cloud**: Cloud SaaS
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Enterprise (Fortune 50 to Am Law 50; $2T+ market cap protected)
- **Pricing**: Freemium hook ("Get 5 free vendors for assessments and monitoring") + enterprise sales
- **Differentiators**: TPRM/vendor-AI risk intelligence niche (26 risk vectors mapped to NIST AI RMF, OWASP LLM Top 10, MITRE Atlas); monitors vendor AI change cadence ("Claude and ChatGPT Connectors Change Every 9 Minutes"); training-data opt-out visibility; indirect prompt injection assessment across vendor connectors; research on Claude/Google/Slack/Writer.com exfil; legal/privacy workflows
- **Evidence date**: 2026-10-01

### Gretel → NVIDIA (NeMo Synthetic Data)
- **URL**: https://gretel.ai/ (now NVIDIA NeMo synthetic data pages)
- **Category**: Synthetic data generation (privacy-preserving data alternative) — NOT a prompt-injection firewall
- **Core claims**: "Synthetic Data Generation for Agentic AI"; privacy-safe versions of sensitive data (HIPAA/GDPR configurations)
- **Pre-execution vs post-hoc**: N/A (data synthesis, not runtime blocking)
- **Local-first vs cloud**: NVIDIA cloud / enterprise
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Enterprise / developer
- **Differentiators**: Acquired by NVIDIA; synthetic data for training/eval without sharing real sensitive data; NeMo Safe Synthesizer for HIPAA/GDPR privacy-safe data
- **Market note**: Fourth consolidation — Gretel no longer independent AI-security vendor
- **Evidence date**: 2026-10-01

---

## Category 2: AI Gateways / Observability with Security

### Helicone
- **URL**: https://www.helicone.ai/
- **Category**: LLM observability / monitoring / routing (gateway-adjacent, NOT security-first)
- **Core claims**: "Build Reliable AI Apps"; route, debug, and analyze LLM applications
- **Pre-execution vs post-hoc**: Observability / analytics (post-hoc); not a security firewall
- **Local-first vs cloud**: Cloud SaaS (open-source option)
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Developer / startups → enterprise
- **Pricing**: Free trial (7-day), tiered SaaS pricing
- **Differentiators**: Open-source LLM observability; integrations (OpenAI, Anthropic, Azure, LiteLLM); YC-backed
- **Market note**: **Helicone joins Mintlify** (banner on homepage 2026) — consolidation in observability layer
- **Evidence date**: 2026-10-01

### Portkey → Palo Alto Networks Prisma AIRS AI Gateway
- **URL**: https://portkey.ai/ (now PRISMA AIRS AI Gateway)
- **Category**: AI gateway / LLMOps platform with security features
- **Core claims**: "Production Stack for Gen AI Builders"; AI Gateway, Observability, Guardrails, Governance, Prompt Management
- **Pre-execution vs post-hoc**: Both — PII redaction before LLM call (pre) + observability (post)
- **Local-first vs cloud**: Hybrid ("gateway in our network with the control plane SaaS") + SaaS
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Developer + enterprise (RBAC, SSO, budget limits)
- **Pricing**: Freemium + paid tiers; budget limits feature
- **Differentiators**: 1600+ LLMs unified API; MCP Gateway (centralized auth/access/observability of MCP servers); cost attribution & budget limits; open-sourced LLM pricing dataset; now absorbed into Palo Alto Prisma AIRS (GA July 2026)
- **Market note**: FIFTH consolidation — Portkey absorbed into Palo Alto alongside Protect AI
- **Evidence date**: 2026-10-01

### LiteLLM
- **URL**: https://www.litellm.ai/
- **Category**: AI gateway for platform teams (routing, governance, observability, cost control)
- **Core claims**: "The AI Gateway for platform teams"; put full AI stack behind one key; see who drives spend, cap it before it runs
- **Pre-execution vs post-hoc**: Both — spend caps / budget enforcement (pre-execution) + observability (post)
- **Local-first vs cloud**: **Self-hosted / local-first primary** ("Self-host in minutes"); also enterprise SaaS
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Developer/platform teams + enterprise (NVIDIA, Netflix, AT&T, Okta, SAP, IBM)
- **Pricing**: Open source (Start free) + Enterprise (Talk to sales); virtual keys with spend/budget limits
- **Differentiators**: **Agent/cost governance (strong)** — spend tracking per key/team, budget caps before run, 56% cost reduction claim (AT&T); self-hosted gateway (local-first enforcement); 140+ providers / 1800+ models; MCP + agent routing; SSO + secret manager integration; Rust migration
- **Evidence date**: 2026-10-01

### LangSmith / LangChain
- **URL**: https://www.langchain.com/ (LangSmith platform)
- **Category**: Agent engineering platform / LLM observability + governance
- **Core claims**: Accelerating the Agent Development Lifecycle (Build, Test, Deploy, Monitor, Iterate, Govern)
- **Pre-execution vs post-hoc**: Both — Govern step: "Enforce cost limits and detect sensitive data before damage happens" (pre) + Monitor/online evals (post)
- **Local-first vs cloud**: Cloud SaaS (LangSmith); open-source frameworks (LangChain, LangGraph, Deep Agents)
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Developer + enterprise (7K+ LangSmith customers, 5 of Fortune 10)
- **Pricing**: Freemium + enterprise
- **Differentiators**: **Agent cost governance** (enforce cost limits) + sensitive data detection in Govern; full agent lifecycle (LangSmith Fleet, Sandboxes, Deployment); 350M+ monthly OSS downloads; Klarna/ServiceNow/CH Robinson case studies
- **Evidence date**: 2026-10-01

### Braintrust
- (queued next)
### Braintrust
- **URL**: https://www.braintrust.dev/
- **Category**: Agent observability + evals platform (quality-first, security-adjacent)
- **Core claims**: "Ship quality agents at scale"; Discover patterns, turn into evals, improve quality
- **Pre-execution vs post-hoc**: Mostly post-hoc (observability/evals); some pre-release gating ("Block bad releases before they hit production")
- **Local-first vs cloud**: Cloud SaaS
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Developer + enterprise (Stripe, Notion, Instacart, Vercel, Dropbox, Ramp, MongoDB, Cloudflare)
- **Pricing**: Freemium + contact sales
- **Differentiators**: Loop agent (auto-generate prompts/scorers/datasets); Pattern automations; evidence-backed pattern discovery; MCP server for IDE; cost/latency/quality tracking; framework-agnostic; NOT a security firewall — quality/evals focus
- **Evidence date**: 2026-10-01

---

## Category 3: Agent Guardrails

### NVIDIA NeMo Guardrails
- **URL**: https://github.com/NVIDIA-NeMo/Guardrails | https://docs.nvidia.com/nemo/guardrails
- **Category**: Open-source programmable agent/LLM guardrails toolkit
- **Core claims**: Open-source toolkit for adding programmable guardrails to LLM-based conversational apps; control output (topics, dialog paths, language style, structured data extraction)
- **Pre-execution vs post-hoc**: Pre-execution (rails sit between application code and LLM)
- **Local-first vs cloud**: **Local-first / self-hosted** — pip install library, runs in your stack (Apache 2.0)
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Developer / open source + enterprise NVIDIA ecosystem
- **Pricing**: Free / open source (Apache 2.0)
- **Differentiators**: Programmable Colang rails; input/output/dialog/retrieval rails; academic foundation (arXiv 2310.10501); v0.24.1 active; **local-first enforcement is a core design property** (vs cloud gateways)
- **Evidence date**: 2026-10-01

### Guardrails AI
- (queued next)
### Guardrails AI → Harvey
- **URL**: https://www.guardrailsai.com/
- **Category**: AI reliability platform / open-source guardrails framework + synthetic data
- **Core claims**: "The AI Reliability Platform"; guardrails framework for building, governing, scaling production GenAI
- **Pre-execution vs post-hoc**: Pre-execution — "Deploy runtime guardrails that detect policy violations, hallucinations, and data leakage. Block bad outputs before they reach users"
- **Local-first vs cloud**: Open-source Guardrails (local library) + Snowglobe cloud simulation
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Enterprise + startups + government (Masterclass, Changi Airport)
- **Pricing**: Open source + enterprise (Talk to Us)
- **Differentiators**: Guardrails Hub validators; Snowglobe synthetic persona simulation; multi-LLM / multi-deployment; now **joined Harvey** (legal AI) — consolidation
- **Market note**: SIXTH consolidation — Guardrails AI absorbed into Harvey
- **Evidence date**: 2026-10-01

### Microsoft Purview AI (DSPM for AI)
- **URL**: https://learn.microsoft.com/en-us/purview/ai-microsoft-purview
- **Category**: Enterprise DLP / data security & compliance for AI apps (covers "Enterprise DLP for ChatGPT/Copilot")
- **Core claims**: Mitigate and manage risks associated with AI usage; DSPM for AI; protection and governance for Copilots and agents
- **Pre-execution vs post-hoc**: Both — sensitivity labels + DLP policies applied to AI interactions (pre/during) + compliance monitoring (post)
- **Local-first vs cloud**: Microsoft cloud (M365/Azure ecosystem)
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Enterprise (M365 E5-class licensing)
- **Pricing**: Microsoft 365 / Purview licensing (enterprise)
- **Differentiators**: Covers Copilot suite + Entra-registered AI apps + ChatGPT Enterprise + Anthropic Claude Enterprise + "Other AI apps" via Defender for Cloud Apps catalog (ChatGPT, Gemini, DeepSeek); sensitivity labels for AI; Microsoft Agent 365 governance; one-click policies; deep M365 integration
- **Evidence date**: 2026-10-01

### Anthropic / OpenAI Built-in Guardrails
- **URL**: (platform docs; Anthropic Constitutional Classifiers / OpenAI Moderation + Safety)
- **Category**: Model-provider built-in safety/guardrails
- **Core claims**: Anthropic: Constitutional Classifiers, jailbreak resistance, prompt injection mitigations in Claude; OpenAI: Moderation API, instruction hierarchy, safety systems for ChatGPT/Agents
- **Pre-execution vs post-hoc**: Pre-execution (model-level refusals/classifiers) + post-hoc moderation
- **Local-first vs cloud**: Cloud API (model provider hosted)
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Both (consumer products + enterprise APIs)
- **Pricing**: Bundled with model API usage
- **Differentiators**: Deepest model-native integration; no third-party hop; limited portability across models; enterprise features (Claude Compliance API used by Nightfall/Lasso)


---

## Category 4: AI Red Teaming

### TrojAI → A10 Networks (TrojAI by A10)
- **URL**: https://www.a10networks.com/products/trojai-by-a10/
- **Category**: AI runtime defense + agent-led red teaming platform
- **Core claims**: "Secure every AI agent, application, model from build to runtime"; TrojAI Defend (runtime) + TrojAI Detect (red teaming) + TrojAI Defend for MCP
- **Pre-execution blocking vs post-hoc**: Both — Defend blocks prompt injection/jailbreak/data leakage/toxic content in real time (pre-execution) + Detect continuous red teaming (pre-deployment)
- **Local-first vs cloud**: **Local-first / self-contained** — "Deploy Anywhere: Maintain full control, privacy, and security over your models, agents, and data with a self-contained deployment on-premises or in your own cloud"
- **Crypto receipts/proofs**: Not mentioned
- **Consumer vs enterprise**: Enterprise
- **Pricing**: Sales-led
- **Differentiators**: Acquired by A10 Networks; agent-led red teaming (single-turn, multi-turn, agentic attacks); thousands of out-of-box adversarial scenarios; proprietary fine-tuned adversarial models; MCP server discovery/policy/blocking; OWASP/MITRE/NIST mapping; **on-prem self-contained deployment (rare vs cloud-only peers)**
- **Market note**: SEVENTH consolidation — TrojAI absorbed into A10 Networks
- **Evidence date**: 2026-10-01

### Gradient (gradient.ai)
- **URL**: https://gradient.ai/ (now shows "Hyperagent" — agent fleet product)
- **Category**: HISTORICAL: AI red teaming / ML model security; CURRENT: agent fleet product (Hyperagent)
- **Status**: Site rebranded/pivoted to Hyperagent ("Agents that ship real, powerful work") — NOT an AI security/red teaming product as of 2026-10-01
- **Note**: Original Gradient AI security/red teaming offering no longer appears on primary site; treat as exited/pivoted from AI security market
- **Evidence date**: 2026-10-01

### Holistic AI
- (queued next)
### Holistic AI
- **URL**: https://www.holisticai.com/
- **Category**: Enterprise AI governance platform (GRC + risk testing + policy enforcement)
- **Core claims**: "AI Governance that Accelerates Transformation"; Discover every model/agent/app; assess AI risk; enforce policies; continuous governance
- **Pre-execution blocking vs post-hoc**: Both — deployment gates / Guardian Agents that "block, redirect or escalate" (pre) + continuous monitoring / drift detection (post)
- **Local-first vs cloud**: Cloud SaaS (connects to AWS, Azure, GitHub, Databricks; 20+ integrations)
- **Crypto receipts/proofs**: Not mentioned (audit-ready evidence / audit trail)
- **Consumer vs enterprise**: Enterprise (Unilever, eBay, Siemens, GSK, GE HealthCare, Publicis)
- **Pricing**: Sales-led (Book a demo)
- **Differentiators**: Gartner Magic Quadrant Challenger 2026 AI Governance Platforms; EU AI Act / NIST AI RMF / ISO 42001 control mapping; 40+ bias/hallucination/privacy/robustness tests; Guardian Agents; shadow AI discovery; red teaming for prompt injection/jailbreaks; compliance evidence automation
- **Evidence date**: 2026-10-01

---

## UNIQUE / RARE CAPABILITY SCAN
(Searching market for claimed differentiators)

### Cryptographic portable receipts for AI outputs
- **Market status**: EMERGING NICHE — not offered by any mainstream AI-security vendor in this competitive set
- **Found (not in primary competitor list)**:
  - VeridexCore (veridexcore.com): "Add cryptographic proof to any AI output in one API call. Deterministic receipts, Merkle-anchored attestations, and public verification"
  - IETF draft-chueayen-attestation-receipts (standards track)
  - PyPI: llm-attestation, llm-receipts
  - thehiveiriq.com "cryptographic AI receipts"
- **Mainstream vendors (Lakera, F5, HiddenLayer, Nightfall, etc.)**: NONE claim cryptographic portable receipts; they offer audit logs / traceability / lineage only
- **Rarity assessment**: **RARE/UNIQUE** among enterprise AI security platforms as of 2026

### Local-first enforcement
- **Market status**: UNCOMMON but present in a few vendors
- **Who has it**:
  - NVIDIA NeMo Guardrails (open-source library, runs in-process) — strongest local-first design
  - F5 AI Guardrails (on-prem + fully air-gapped "Private AI")
  - TrojAI by A10 (self-contained on-prem or own-cloud deployment)
  - LiteLLM (self-hosted gateway)
  - HiddenLayer AIDR (non-invasive, no customer data/model access needed)
- **Most competitors**: cloud SaaS only
- **Rarity assessment**: **RARE as a first-class product claim**; a meaningful differentiator when combined with crypto receipts

### Agent cost governance
- **Market status**: PRESENT but not universal
- **Who has it**:
  - Arthur AI (strongest: token spend by team/user, auto-reroute to cheaper models, 62% rerouted claim)
  - LiteLLM (virtual keys with spend/budget caps before run)
  - LangSmith Govern step ("Enforce cost limits")
  - Portkey/Prisma AIRS (budget limits, cost attribution)
  - Braintrust (cost tracking in observability)
- **Rarity assessment**: **UNCOMMON as a security-control feature**; often buried in FinOps/gateway rather than agent security

### Islamically-grounded maqasid ethics layer
- **Market status**: **NOT FOUND as a commercial product**
- **What exists**: Academic papers only (e.g., "Toward an Islamic Ethics and Fiqh of Artificial Intelligence" June 2026; "AI, Shariah Governance, and Maqasid Shariah in Islamic Finance" Oct 2025)
- **Rarity assessment**: **UNIQUE** — no commercial AI security/governance product claims maqasid-based ethics

### Mathematical novelty detectors
- **Market status**: **NOT FOUND as a commercial AI security product category**
- **What exists**: Research/academic anomaly/novelty detection; some "intent analysis"/"behavioral anomaly" marketing (Lasso, Arthur ABA) but not mathematical novelty detection as a distinct product claim
- **Rarity assessment**: **UNIQUE** if implemented with formal mathematical novelty guarantees

### Zero-day exploit pipeline (AI)
- **Market status**: Partial analogs exist (red teaming / attack libraries) but not a true zero-day exploit pipeline
- **Closest**: Lakera (1M+ hacker community), F5 (10k+ attack patterns/month), TrojAI (thousands of adversarial scenarios), Pillar (military-intel research, sandbox escape/MCP vulns), HiddenLayer (CVE disclosures)
- **Rarity assessment**: **RARE** as an industrialized zero-day pipeline specifically for AI/agent exploits; most do continuous red-team / threat intel, not 0-day production

### Threshold crypto / DKG for AI agent governance
- **Market status**: **NOT FOUND in AI security products**
- **What exists**: Blockchain/custody (CertiK DKG posts, FDKG, academic IACR papers) — orthogonal to LLM security vendors
- **Rarity assessment**: **UNIQUE** if applied to AI agent governance/policy keys

### Silent-speech / biometric privacy
- **Market status**: **NOT FOUND in AI security competitor set**
- **What exists**: Adjacent privacy tech (EEG/silent speech interfaces research); not in LLM/agent security products
- **Rarity assessment**: **UNIQUE** as an AI-agent-governance privacy control

---

## MARKET STRUCTURE SUMMARY (2026)

### Extreme consolidation wave
| Original vendor | Acquirer / fate |
|---|---|
| Protect AI / LLM Guard | Palo Alto Networks (Prisma AIRS) |
| Portkey | Palo Alto Networks (Prisma AIRS AI Gateway) |
| CalypsoAI | F5 (AI Guardrails) |
| Robust Intelligence | F5 (AI Guardrails) |
| Prompt Security | SentinelOne (standalone shut down; domain for sale) |
| Lakera | Check Point |
| Gretel | NVIDIA (NeMo synthetic data) |
| Guardrails AI | Harvey |
| TrojAI | A10 Networks |
| Helicone | Mintlify (joining) |
| Gradient | Pivoted to Hyperagent (exited AI security) |

### Still independent (primary list)
HiddenLayer, Arthur, Lasso Security, Pillar Security, Prompt Armor, Nightfall AI, LiteLLM, LangSmith, Braintrust, NVIDIA NeMo Guardrails, Microsoft Purview AI, Holistic AI

### Category pattern
- Runtime prompt-injection firewalls are consolidating into platform security majors (Palo Alto, F5, Check Point, SentinelOne, A10)
- Gateways are absorbing security (Portkey→Prisma AIRS; LiteLLM adds governance; LangSmith adds Govern)
- Guardrails frameworks are either open-source (NeMo) or acquired (Guardrails AI→Harvey)
- Governance/GRC (Holistic AI, Prompt Armor, Purview) remains more fragmented
- **White space**: cryptographic portable receipts, maqasid ethics, mathematical novelty detectors, threshold crypto/DKG, silent-speech privacy are essentially uncontested

