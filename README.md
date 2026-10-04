# SentinAI 🛡️

**SentinAI** is a high-performance, Explainable AI (XAI) static malware analysis engine. Designed to detect malicious Portable Executables (PE) without requiring dynamic execution, SentinAI leverages Machine Learning and cryptographic analysis to provide real-time threat intelligence.

![SentinAI Dashboard Demo](https://img.shields.io/badge/UI-TailwindCSS-06B6D4?style=flat-square&logo=tailwindcss)
![Backend](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi)
![AI/ML](https://img.shields.io/badge/AI-Random_Forest-F7931E?style=flat-square&logo=scikit-learn)

## 🚀 Features

* **Static Heuristic Analysis:** Parses Windows PE headers (MZ/PE) to extract 54 critical structural features without detonating the payload.
* **Explainable AI (XAI):** Integrates **SHAP (SHapley Additive exPlanations)** to generate visual waterfall plots. This ensures the AI's decision-making process is completely transparent, highlighting exactly which PE headers contributed to the final threat verdict.
* **Adaptive Threat Scoring:** Utilizes a Random Forest classifier with dynamic confidence thresholds to minimize false positives on packed or digitally signed benign executables.
* **Modern Web Architecture:** Powered by a blazing-fast **FastAPI** backend and a stunning, responsive **TailwindCSS / Vanilla JS** frontend utilizing glassmorphism design principles.
* **Memory Topology & Entropy:** Calculates Shannon Entropy across memory sections to identify potentially encrypted, packed, or obfuscated malware payloads.

## 🧠 Architecture

1. **Frontend:** Static `index.html` served natively. Uses TailwindCSS for a sleek, dark-mode macOS/VisionOS aesthetic.
2. **Backend:** FastAPI handles concurrent binary uploads, file parsing via `pefile`, and cryptographic hashing in memory.
3. **Machine Learning Pipeline:** Pre-trained Random Forest model (`malware_detector.pkl`) evaluates the extracted feature vector and returns probability distributions. SHAP visualizes the feature importance.

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/SentinAI.git
   cd SentinAI
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   .\.venv\Scripts\activate  # On Windows
   ```

3. **Install dependencies:**
   ```bash
   pip install fastapi uvicorn python-multipart pefile scikit-learn pandas shap matplotlib joblib
   ```

4. **Run the Application:**
   ```bash
   python main.py
   ```
   *The application will be available at `http://localhost:8000`*

## 🔬 Use Cases
* Initial triage for Security Operations Centers (SOC).
* Academic research in Machine Learning applications for Cybersecurity.
* Safe, static extraction of Indicators of Compromise (IOCs).

## 📄 License
This project was developed in 2025. All rights reserved.
