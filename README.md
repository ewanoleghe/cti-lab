# CTI-Lab Dashboard

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)]
[![FastAPI](https://img.shields.io/badge/FastAPI-0.135+-green?logo=fastapi&logoColor=white)]
[![React](https://img.shields.io/badge/React-19+-61DAFB?logo=react&logoColor=white)]
[![Vite](https://img.shields.io/badge/Vite-6+-646CFF?logo=vite&logoColor=white)]
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]

Real-time **Cyber Threat Intelligence (CTI)** dashboard for monitoring global threats and company-specific risks.

---

## Table of Contents
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Security Tips](#security-tips)
- [License](#license)
- [Credits / Contact](#credits--contact)

---

## Features
- Global CTI feed: RSS, CISA KEV, vulnerabilities, threat intel, malware research, blogs
- Company-specific alerts: phishing, breaches, Shodan exposures, domain impersonation, paste/leak mentions
- Modern UI: React + Vite + Tailwind CSS with dark mode
- Backend: FastAPI + SQLite + scheduled collector (every 2 hours)
- One-command start: backend + collector + frontend

---

## Architecture
**Backend:**
- Collector (`app/collector.py`), FastAPI API (`app/api.py`), SQLite database (`cti_lab.db`)

**Frontend:**
- React + Vite in `ui/`, Tailwind CSS, responsive design

---

## Prerequisites
- Python 3.10+
- Node.js 18+ / npm
- Git

---

## Quick Start
```bash
git clone https://github.com/ewanoleghe/cti-lab.git
cd cti-lab

# Python backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Frontend
cd ui
npm install
cd ..

# Copy .env and configure API keys
cp .env.example .env

# Start everything
npm run dev:all

## Usage
- Navigate to `http://localhost:5173` to view the dashboard
- Global threat feeds and company-specific alerts update automatically
- Monitor CTI, breaches, phishing, leaks, and web mentions in real-time

## Security Tips
- Never commit `.env` or files containing API keys
- Add `.env` to `.gitignore`
- Rotate API keys regularly
- Backup SQLite database securely

## License
MIT License — see [LICENSE](./LICENSE)

## Credits / Contact
Created by **Ewan Oleghe**  
Portfolio: [https://ewanoleghe.github.io/](https://ewanoleghe.github.io/)

Happy threat hunting! 🕵️‍♂️💻

