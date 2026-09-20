# TRACE — Don’t Just Detect. Investigate.

> **Don’t just detect. Investigate.**

TRACE is a multi-agent AI cybersecurity investigation system that analyzes suspicious digital evidence such as scam messages, phishing attempts, suspicious URLs, and screenshots.

Instead of simply answering **“Is this a scam?”**, TRACE performs an investigation.

It extracts evidence, analyzes the case from multiple perspectives, challenges its own findings through a **Devil’s Advocate** agent, and produces an evidence-backed final assessment through a **Judge Agent**.

---

## The Problem

Scam and phishing detection systems often reduce a complex situation to a simple classification:

> ❌ Scam  
> ✅ Safe

But real-world suspicious messages are rarely that simple.

A message may contain:

- Impersonation
- Urgency or fear tactics
- Suspicious payment requests
- Malicious or deceptive URLs
- Fake authority
- Social-engineering patterns
- Conflicting or incomplete information

Users need more than a label.

They need to understand:

> **Why is this suspicious? What evidence supports that conclusion? Could the conclusion be wrong? What should I do next?**

---

# Our Solution

TRACE treats suspicious content as an **investigation case** rather than a classification problem.

### Core flow

```text
                 ANY SOURCE
                     │
                     ▼
          ┌─────────────────────┐
          │ Universal Evidence  │
          │       Intake        │
          └──────────┬──────────┘
                     │
            Screenshot / Text / URL
                     │
                     ▼
          ┌─────────────────────┐
          │ Evidence Extraction │
          └──────────┬──────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
   Evidence      Social          Threat
    Agent      Engineering    Intelligence
                  Agent           Agent
        │            │            │
        └────────────┼────────────┘
                     ▼
             Investigation State
                     │
                     ▼
          ┌─────────────────────┐
          │  Devil's Advocate   │
          │ "Attack This Verdict"│
          └──────────┬──────────┘
                     │
                     ▼
             ┌───────────────┐
             │  Judge Agent  │
             └───────┬───────┘
                     │
                     ▼
              Final Assessment
                     │
                     ▼
          Evidence + Reasoning
          + Counter-Evidence
          + Recommended Actions
```

---

# What Makes TRACE Different?

## 1. Multi-Agent Investigation

TRACE does not rely on a single AI response.

Different agents investigate different aspects of the same evidence.

### Evidence Agent

Extracts structured information from the submitted evidence.

Examples:

- URLs
- Phone numbers
- Names
- Organizations
- Dates
- Monetary amounts
- Claims
- Suspicious phrases
- Other relevant indicators

---

### Social Engineering Agent

Analyzes the psychological and social-engineering characteristics of the content.

It looks for patterns such as:

- Urgency
- Fear
- Threats
- Authority impersonation
- Reward/lure tactics
- Credential requests
- Payment pressure
- Identity impersonation
- Manipulative language

---

### Threat Intelligence Agent

Analyzes indicators against trusted cybersecurity knowledge and available intelligence.

Potential indicators include:

- Suspicious domains
- Known phishing patterns
- Scam techniques
- Malicious indicators
- Domain characteristics
- Known attack patterns

The MVP can use a curated/trusted knowledge base rather than depending on unrestricted external APIs.

---

# 2. Devil's Advocate

This is one of TRACE's core features.

Most AI systems try to reach an answer.

TRACE also asks:

> **"What if we're wrong?"**

The Devil's Advocate agent receives the investigators' findings and actively attempts to challenge them.

It searches for:

- Contradictory evidence
- Weak assumptions
- Missing information
- Alternative explanations
- Overconfident conclusions
- Evidence that could support a benign interpretation

This creates an adversarial verification stage before the final decision.

---

# 3. Attack This Verdict

Users can explicitly ask TRACE to challenge its own conclusion.

### Example

TRACE initially concludes:

> **HIGH RISK**

The user clicks:

> **Attack This Verdict**

TRACE then performs another adversarial analysis.

The system can surface:

- Why the original verdict might be wrong
- Which assumptions were weak
- What evidence contradicts the conclusion
- What additional evidence would change the assessment

The final Judge can then maintain or revise the assessment based on the counter-analysis.

---

# 4. Evidence → Reasoning → Counter-Evidence → Verdict

TRACE is designed to make the investigation **auditable**.

Instead of:

```text
SCAM: TRUE
```

TRACE aims to provide:

```text
Evidence
   ↓
Independent Findings
   ↓
Cross-analysis
   ↓
Counter-arguments
   ↓
Final Assessment
   ↓
Recommended Actions
```

The goal is not simply to produce an answer.

The goal is to show **how the answer was reached**.

---

# Universal Evidence Intake

TRACE does not require direct access to a user's messaging account.

For the hackathon MVP, users can provide suspicious content as:

### Supported inputs

- Screenshot / image
- Text
- URL

For example, a user can upload a screenshot of a suspicious WhatsApp message.

TRACE analyzes the screenshot itself.

It does **not** need access to the user's entire WhatsApp account.

### Privacy principle

> **TRACE investigates the artifact, not the platform.**

This makes the system more platform-independent and avoids requiring direct integrations with WhatsApp, SMS, Telegram, or other messaging platforms.

---

# Example Investigation

Imagine a user receives:

> "URGENT: Your bank account will be blocked today. Verify your KYC immediately using the link below."

The user uploads a screenshot.

TRACE can identify:

### Extracted evidence

```text
Claim:
Bank account will be blocked

URL:
example-suspicious-domain.com

Behavior:
Requests immediate action

Language:
Urgent / threatening

Potential target:
Banking credentials
```

### Evidence Agent

Finds:

- Suspicious URL
- Financial context
- Urgency
- Account-related claim

### Social Engineering Agent

Finds:

- Fear
- Urgency
- Authority impersonation
- Pressure to act immediately

### Threat Intelligence Agent

Checks:

- Domain information available to the system
- Relevant phishing/scam knowledge
- Similar attack patterns

### Devil's Advocate

Challenges the findings:

```text
Could this be a legitimate bank notification?

What evidence supports legitimacy?

Which indicators are assumptions rather than facts?
```

### Judge Agent

Synthesizes the investigation and produces a final assessment.

---

# Final Investigation Report

A TRACE investigation is designed to return structured information such as:

```json
{
  "case_id": "TRC-001",

  "evidence": {
    "type": "image",
    "extracted_text": "...",
    "urls": [],
    "entities": []
  },

  "agents": {
    "evidence": {
      "findings": [],
      "indicators": []
    },

    "social_engineering": {
      "findings": [],
      "indicators": []
    },

    "threat_intelligence": {
      "findings": [],
      "indicators": []
    }
  },

  "devils_advocate": {
    "challenges": [],
    "counter_evidence": []
  },

  "verdict": {
    "risk_level": "HIGH",
    "confidence": 0.87,
    "reasoning": [],
    "recommended_actions": []
  }
}
```

The exact schema may evolve during implementation.

The frontend can use this structured response to display the investigation as a sequence of stages rather than presenting only a final answer.

---

# System Architecture

```text
                         ┌───────────────┐
                         │   React UI    │
                         └───────┬───────┘
                                 │
                                 ▼
                         ┌───────────────┐
                         │ API Gateway / │
                         │ Backend API   │
                         └───────┬───────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
             ┌─────────────┐          ┌─────────────┐
             │ Amazon S3    │          │ DynamoDB    │
             │ Evidence    │          │ Case State  │
             └─────────────┘          └──────┬──────┘
                                             │
                                             ▼
                                  ┌────────────────────┐
                                  │ Amazon Bedrock     │
                                  │ / AgentCore        │
                                  └─────────┬──────────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    │                       │                       │
                    ▼                       ▼                       ▼
             Evidence Agent       Social Engineering       Threat Intelligence
                                      Agent                    Agent
                    │                       │                       │
                    └───────────────────────┼───────────────────────┘
                                            ▼
                                  Investigation State
                                            │
                                            ▼
                                  Devil's Advocate
                                            │
                                            ▼
                                      Judge Agent
                                            │
                                            ▼
                                    Final Report
```

---

# AWS Technology Stack

TRACE is designed around AWS services suitable for an AI-powered investigation workflow.

| AWS Service | Purpose |
|---|---|
| **Amazon Bedrock** | Foundation models and AI reasoning |
| **Amazon Bedrock AgentCore** | Agent execution/orchestration and tool access |
| **Amazon Bedrock Knowledge Bases** | Trusted cybersecurity/scam knowledge |
| **Amazon Bedrock Data Automation** | Structured extraction from supported evidence where applicable |
| **Amazon Bedrock Guardrails** | Safety and responsible AI controls |
| **Amazon S3** | Secure storage of uploaded evidence |
| **Amazon DynamoDB** | Investigation/case state |
| **AWS Lambda** | Backend processing/orchestration where appropriate |
| **Amazon API Gateway** | API layer where appropriate |

The final implementation may simplify or replace individual components depending on hackathon-time constraints.

---

# Investigation State

TRACE maintains a structured representation of each investigation.

Conceptually:

```text
CASE
│
├── Original Evidence
│
├── Extracted Evidence
│   ├── Text
│   ├── URLs
│   ├── Entities
│   └── Indicators
│
├── Agent Findings
│   ├── Evidence Agent
│   ├── Social Engineering Agent
│   └── Threat Intelligence Agent
│
├── Challenges
│   └── Devil's Advocate
│
└── Verdict
    ├── Risk Level
    ├── Confidence
    ├── Reasoning
    └── Recommended Actions
```

This shared investigation state allows agents to contribute findings without requiring every agent to be given a pre-generated answer.

---

# Important Design Principle

TRACE should **not** make every agent see a predetermined conclusion.

Instead:

```text
Original Evidence
       │
       ├──► Evidence Agent
       │
       ├──► Social Engineering Agent
       │
       └──► Threat Intelligence Agent
                    │
                    ▼
            Independent Findings
                    │
                    ▼
             Devil's Advocate
                    │
                    ▼
                Judge Agent
```

This creates a more meaningful investigation pipeline than simply asking several agents to agree with the same answer.

---

# MVP Scope

The hackathon MVP focuses on one complete investigation pipeline.

### Input

- [x] Screenshot/image (base64)
- [x] Text
- [x] URL (with SSRF protection)

### Investigation

- [x] Evidence extraction
- [x] Social-engineering analysis
- [x] Threat/scam intelligence analysis
- [x] Devil's Advocate (adversarial challenges)
- [x] Judge Agent (final synthesis)
- [x] Structured investigation state

### Output

- [x] Risk assessment (LOW/MEDIUM/HIGH/CRITICAL)
- [x] Investigation reasoning
- [x] Supporting evidence
- [x] Counter-evidence
- [x] Recommended actions
- [x] Agent-by-agent findings

### Interface

- [x] Evidence upload (text, URL, image)
- [x] Investigation progress visualization
- [x] Agent findings display
- [x] Verdict visualization
- [x] Attack This Verdict (adversarial re-review)

---

# Out of Scope for the MVP

To keep the system reliable and buildable within the hackathon timeframe, TRACE will **not** depend on:

- Direct WhatsApp account integration
- Direct SMS integration
- Direct Telegram account integration
- Reading a user's entire messaging history
- Large-scale automated surveillance
- Complex browser automation
- A large number of external threat-intelligence APIs

These can be explored as future extensions.

---

# Future Scope

Possible future versions of TRACE could support:

- Browser extension
- Share-to-TRACE workflow
- Telegram bot
- WhatsApp Business / Cloud API integration
- Additional messaging platforms
- Live URL reputation services
- DNS/domain intelligence
- Email integration
- Organization-level scam investigation
- Case history and investigation management
- Additional specialized investigation agents

These are **future directions**, not dependencies of the hackathon MVP.

---

# Privacy & Security

TRACE is designed around a minimal-evidence approach.

Instead of requesting access to an entire communication platform, users submit the specific artifact they want investigated.

### Principle

> **Investigate the evidence, not the account.**

The system should:

- Process only submitted evidence
- Avoid unnecessary collection of user data
- Apply appropriate input/output safety controls
- Avoid exposing sensitive information unnecessarily
- Clearly communicate uncertainty in AI-generated assessments

---

# Responsible AI

TRACE is an investigative assistant, not an absolute authority.

A generated assessment can be wrong.

Therefore, the system should distinguish between:

- Observed evidence
- AI interpretation
- Supporting evidence
- Counter-evidence
- Missing information
- Recommended next steps

The `confidence` field represents the system's assessment confidence and should **not** be interpreted as a statistically calibrated probability unless calibration has actually been performed.

Users should verify important claims through trusted official sources before taking consequential action.

---

# Why Multi-Agent?

Different types of evidence require different types of reasoning.

A single model can theoretically perform all of these tasks, but separating investigation roles provides:

```text
Specialization
     +
Independent Findings
     +
Adversarial Challenge
     +
Final Synthesis
     =
Auditable Investigation
```

TRACE therefore treats AI agents as **investigators**, not simply as multiple chatbots.

---

# Project Structure

The exact structure may evolve during development, but the project is expected to follow a separation similar to:

```text
TRACE/
│
├── frontend/
│   ├── components/
│   ├── pages/
│   ├── services/
│   └── ...
│
├── backend/
│   ├── api/
│   ├── agents/
│   │   ├── evidence/
│   │   ├── social_engineering/
│   │   ├── threat_intelligence/
│   │   ├── devils_advocate/
│   │   └── judge/
│   │
│   ├── models/
│   ├── services/
│   └── ...
│
├── knowledge/
│   └── ...
│
├── tests/
│   └── ...
│
├── docs/
│   └── ...
│
├── .env.example
├── README.md
└── ...
```

---

# Getting Started

## Prerequisites

- Node.js 18+
- Python 3.10+
- AWS Account (optional for local development)
- AWS CLI (optional for local development)
- Configured AWS credentials (optional for local development)
- Required Amazon Bedrock model access (for production)

## Clone

```bash
git clone https://github.com/Aditya0850/Serpico.git
cd Serpico
```

## Environment

Create the required environment configuration:

```bash
# Backend
cp backend/.env.example backend/.env

# Frontend
cp frontend/frontend/.env.example frontend/frontend/.env
```

Configure the required AWS and application variables.

> **Never commit AWS credentials, API keys, tokens, or other secrets to the repository.**
> Use `.env.example` files as templates.

---

# Running the Application

## Development Mode (Local)

For local development without AWS, the system runs in **in-memory mode** (`ENV=development`).

### Backend

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8001
```

### Frontend

```bash
cd frontend/frontend
npm install
npm run dev
```

Access the app at `http://localhost:5173` (frontend) with backend at `http://localhost:8001`.

## Production Mode

Set `ENV=production` in `backend/.env` and configure AWS credentials for S3/DynamoDB storage.

```bash
# Backend
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8001

# Frontend
cd frontend/frontend
npm install
npm run build
# Deploy the `dist` folder to your hosting platform
```

---

# Demo Flow

The recommended demonstration:

### 01 — Submit Evidence

Upload a realistic suspicious-message screenshot, paste text, or enter a URL.

### 02 — Evidence Extraction

TRACE extracts:

- Message text
- URLs
- Entities
- Claims
- Indicators

### 03 — Investigation

The specialized agents investigate independently.

### 04 — Adversarial Review

The Devil's Advocate attempts to challenge the emerging conclusion.

### 05 — Judge

The Judge Agent synthesizes:

```text
Evidence
+
Agent Findings
+
Counter-Evidence
+
Investigation Context
```

### 06 — Verdict

TRACE presents:

- Risk level (LOW / MEDIUM / HIGH / CRITICAL)
- Key evidence
- Reasoning
- Counter-evidence
- Recommended actions

### 07 — Attack This Verdict

The user can challenge the result and trigger another adversarial review.

## Verified Test Cases

All flows tested and passing:

| Evidence Type | Input | Expected Risk |
|---------------|-------|---------------|
| Text (scam) | "URGENT: Your account will be suspended! Click http://paypa1.com-security.net..." | MEDIUM |
| Text (legitimate) | "Hello, this is a normal message from a friend." | LOW |
| URL | http://example.com | LOW |
| Image (1x1 PNG) | Base64 encoded PNG | LOW |

---

# Example User Experience

```text
┌─────────────────────────────────────┐
│          TRACE INVESTIGATION        │
├─────────────────────────────────────┤
│                                     │
│  Evidence uploaded ✓                │
│                                     │
│  Evidence Agent            ✓        │
│  Social Engineering Agent  ✓        │
│  Threat Intelligence       ✓        │
│                                     │
│  Devil's Advocate           ✓        │
│                                     │
│  Judge                       ✓      │
│                                     │
├─────────────────────────────────────┤
│          HIGH RISK                  │
│                                     │
│  Why?                               │
│  • Urgency                          │
│  • Authority impersonation          │
│  • Suspicious URL                   │
│  • Payment/credential pressure      │
│                                     │
│  Counter-evidence                   │
│  • No verified sender information   │
│                                     │
│  [ ATTACK THIS VERDICT ]            │
└─────────────────────────────────────┘
```

---

# Evaluation

TRACE can be evaluated using a curated set of representative cases covering:

- Phishing messages
- Banking scams
- Delivery scams
- Account takeover attempts
- Fake government/authority messages
- Job/investment scams
- Benign messages
- Ambiguous cases

Evaluation should consider:

- Evidence extraction quality
- Correct identification of scam indicators
- Quality of reasoning
- Ability to identify counter-evidence
- Consistency of final assessments
- Explainability
- False positives / false negatives

---

# Team

TRACE is built as a collaborative hackathon project.

The team is divided across:

- Backend & AWS architecture
- AI agent orchestration
- Frontend & UX
- Cybersecurity research
- Knowledge-base preparation
- Testing & evaluation
- Integration and deployment

---

# Core Philosophy

Traditional detection asks:

> **"Is this dangerous?"**

TRACE asks:

> **"What evidence do we have?"**

Then:

> **"What does that evidence suggest?"**

Then:

> **"What could prove us wrong?"**

And finally:

> **"What conclusion survives the investigation?"**

---

# TRACE

### Don't just detect. Investigate.

**Evidence → Investigation → Challenge → Verdict**

---
```
