<div align="center">

# 🛡️ SEBI Trust Shield

### Detect the Fake. Authenticate the Real.

AI-powered platform to detect **synthetic media**, **phishing attacks**, and **fraudulent financial communications** in India's securities markets.

![Status](https://img.shields.io/badge/Status-Phase%201-orange)
![Track](https://img.shields.io/badge/Track-Cybersecurity-blue)
![Tech](https://img.shields.io/badge/AI-FastAPI%20%7C%20React-success)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

**SEBI Securities Market TechSprint 2026**

[Overview](#-overview) •
[Features](#-features) •
[Architecture](#-architecture) •
[Tech Stack](#-tech-stack) •
[Roadmap](#-roadmap)

</div>

---

# 📌 Overview

Financial fraud is evolving rapidly through:

- 🎭 Deepfake videos
- 🎙️ Voice cloning
- 📧 AI phishing
- 🌐 Fake broker websites
- 📱 QR scams
- 📢 Fake investment advertisements

Current verification tools require investors to manually search for information.

**SEBI Trust Shield analyzes suspicious financial communications and helps investors verify whether they are genuine before they act.**

---

# 🚀 Key Features

### 🔍 Detection Layer

- URL verification
- WHOIS & SSL validation
- OCR on screenshots
- Scam language detection
- Logo verification
- Risk scoring
- Explainable AI

### ✅ Authentication Layer

- Digital signatures
- QR verification
- Hash validation
- Official communication registry

---

# 🏗️ Architecture

```text
Investor
   │
   ▼
Screenshot / URL / QR / Video
   │
   ▼
Input Router
   │
   ├── OCR
   ├── WHOIS
   ├── SSL
   ├── Domain Similarity
   ├── Logo Detection
   └── AI Analysis
            │
            ▼
     Risk Scoring Engine
            │
            ▼
 Verified ✔️   Suspicious ⚠️
```

---

# ⚙️ Tech Stack

| Layer | Technology |
|--------|------------|
| Frontend | React |
| Backend | FastAPI |
| Language | Python |
| OCR | EasyOCR |
| Database | PostgreSQL |
| Security | Digital Signatures |
| Deployment | Docker + AWS |

---

# 📂 Repository Structure

```text
SEBI_Trust_Shield
│
├── README.md
├── docs/
├── assets/
├── backend/
├── frontend/
├── research/
└── prototype/
```

---

# 🛣️ Roadmap

- ✅ Problem Research
- ✅ Solution Design
- ✅ Architecture
- 🔄 Prototype Development
- ⏳ AI Detection Engine
- ⏳ Authentication Layer
- ⏳ Dashboard
- ⏳ MVP Deployment

---

# 💡 Why This Project?

| Traditional Verification | SEBI Trust Shield |
|--------------------------|-------------------|
| Manual lookup | Automated detection |
| Detect known entities | Analyze unknown content |
| Reactive | Proactive |
| Detection only | Detection + Authentication |

---

# 📊 Current Status

> 🚧 **Phase 1 – Idea Submission**

Completed:

- Research
- Architecture
- Technology Selection

Currently Working On:

- MVP Prototype
- URL Verification Engine
- OCR Pipeline

---

# 👥 Team

**Team Recon**

Astuti Kumari

Mody University of Science and Technology

---

<div align="center">

### ⭐ Building trust in digital financial communications.

*Prototype under active development.*

</div>
