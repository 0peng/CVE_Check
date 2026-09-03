# ORION — Master Product & Engineering Specification
## Evidence-First OSINT Intelligence, Entity Resolution & Behavioral Pattern Analysis Platform
### Version 2.0

---

# 1. Executive Summary

ORION is an evidence-first OSINT intelligence platform designed for authorized analysts working in intelligence, security, investigations, fraud, threat intelligence, risk, and related environments.

ORION's core workflow is:

**Identifier → Identity → Evidence → Relationships → Timeline → Observable Patterns → Analyst Assessment**

The platform is designed to move beyond simple OSINT search.

Its purpose is to connect fragmented public information into a structured intelligence picture while maintaining:

- Evidence provenance
- Explainable confidence
- Identity resolution
- Relationship mapping
- Timeline analysis
- Interest analysis
- Behavioral pattern analysis
- Public-expression analysis
- Change detection
- Analyst review
- Auditability

The central principle is:

> **Evidence before inference.**

ORION must clearly distinguish between:

- What is directly known
- What is observed
- What is correlated
- What constitutes a recurring pattern
- What is an analytical interpretation
- What is only a hypothesis
- What remains unknown

AI is used to accelerate analysis, not to manufacture facts.

---

# 2. Product Vision

ORION should allow an authorized analyst to investigate a target using publicly available and lawfully accessible information and answer questions such as:

### Identity

- Who is this person/entity?
- Which public accounts may belong to the same entity?
- Which identifiers are associated with the entity?
- How strong is the identity resolution?

### Evidence

- What evidence supports the identity?
- What evidence contradicts it?
- Which sources independently corroborate the finding?
- How recent is the evidence?

### Relationships

- Who does the entity publicly interact with?
- What organizations are associated with the entity?
- Which accounts appear connected?
- Which communities or clusters exist?

### Interests

- What topics repeatedly appear?
- What hobbies are publicly observable?
- What professional interests recur?
- What entertainment categories appear frequently?
- What food/cuisine interests are repeatedly observable?

### Places

- What places are explicitly documented?
- Which places were publicly attended?
- Which places were tagged?
- Which destinations are merely mentioned?
- Which locations appear repeatedly in public content?

### Behavioral Patterns

- How frequently does the subject publish public content?
- What patterns repeat?
- Which topics are increasing?
- Which topics are declining?
- Are there observable changes over time?
- Are there changes in public networks?
- Are there changes in public communication patterns?

### Public Political Expression

- What political/public-policy topics has the person publicly discussed?
- What direct public statements exist?
- What political content has been publicly shared?
- What evidence supports each observation?
- Are there contradictions?

### Publicly Disclosed Personal Information

Where legally appropriate and publicly disclosed:

- Publicly stated health information
- Publicly stated career information
- Publicly stated goals
- Publicly stated interests
- Publicly stated affiliations

### Analytical Layer

The system should help analysts answer:

> **What does the available evidence demonstrate, what patterns are observable, how strong are those patterns, and what alternative explanations exist?**

---

# 3. Intended Users

ORION is designed for authorized:

- Intelligence analysts
- Security analysts
- Investigators
- Threat-intelligence analysts
- Fraud investigators
- Risk analysts
- Due-diligence analysts
- Government intelligence/security teams
- Corporate security teams
- Investigative research teams

The deployment organization is responsible for ensuring lawful use, appropriate authorization, privacy controls, retention rules, and applicable jurisdictional requirements.

ORION must not autonomously determine whether a person is:

- Dangerous
- Criminal
- Mentally ill
- Politically acceptable
- Loyal/disloyal
- Trustworthy/untrustworthy
- A security threat

or otherwise suitable for a consequential governmental or organizational action.

---

# 4. Core Product Principles

## 4.1 Evidence Before Inference

Every important analytical claim follows:

**Claim → Evidence → Source → Timestamp → Confidence → Interpretation**

If there is insufficient evidence:

**UNKNOWN**

The system must never fill gaps with fabricated information.

---

## 4.2 Provenance

Each evidence object should contain, where available:

- Evidence ID
- Source ID
- Source type
- Source reference
- URL/reference
- Collection timestamp
- Publication timestamp
- Original content reference
- Content hash
- Extracted statement
- Normalized facts
- Entity association
- Evidence strength
- Source reliability
- Freshness
- Analyst verification status

---

## 4.3 Explainable Confidence

Confidence must be explainable.

Possible factors:

- Source reliability
- Number of independent sources
- Evidence quality
- Evidence freshness
- Identity-link strength
- Corroboration
- Contradictions
- Temporal consistency
- Analyst verification

Avoid unexplained "AI confidence".

---

## 4.4 Fact vs Interpretation

Every analytical object must be explicitly classified.

Supported labels:

```text
FACT
OBSERVATION
CORRELATION
PATTERN
INTERPRETATION
HYPOTHESIS
UNKNOWN
```

---

> **Document status:** the source text supplied for this revision ends at section 4.4.
> Sections 5 and onward are not yet written; append them here as they are provided.
