# 🛡️ ShieldSense

An Explainable AI-powered cybersecurity tool that analyzes suspicious URLs and explains **why** they are risky instead of simply marking them as safe or dangerous.

---

## 🚀 Features

- 🔍 URL Threat Analysis
- 📊 Risk Score (0–100)
- ⚠️ Risk Level Classification
- 🧠 Explainable Risk Breakdown
- 🛡️ Technical Signal Detection
- 💡 Security Recommendations

---

## 🛠️ Tech Stack

### Frontend
- React
- Vite
- JavaScript

### Backend
- FastAPI
- Python
- Pydantic

---

## 📂 Project Structure

```text
ShieldSense/
│
├── backend/
├── frontend/
├── docs/
└── README.md
```

---

## ⚙️ Workflow

```text
User URL
   ↓
React Frontend
   ↓
FastAPI API
   ↓
URL Signal Extraction
   ↓
Risk Engine
   ↓
Explainable Result
```

---

## 🔍 Current Detection Signals

- Missing HTTPS
- IP Address URLs
- Suspicious Keywords
- Long URLs
- Excessive Subdomains
- Punycode Detection
- Brand Impersonation
- @ Symbol Abuse

---

## 🚧 Roadmap

- 📧 Email Phishing Analyzer
- 📱 QR Code Analyzer
- 🤖 AI Explanation Engine
- 📈 Analytics Dashboard

---

## ▶️ Run Locally

### Backend

```bash
cd backend
uvicorn app.main:app --reload
```

Open:

```
http://127.0.0.1:8000/docs
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open:

```
http://localhost:5173
```

---

## 📜 License

This project was developed for a hackathon demonstration.
