# Contributing to RepoGuard

Thank you for your interest in contributing to **RepoGuard**!  
Developed under the **University of Mumbai - Recent Open Source Project Lab (ITL709)**.

---

## 🛠️ Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/example/RepoGuard.git
   cd RepoGuard
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the test suite:**
   ```bash
   python -m pytest -v
   ```

---

## 🚀 Running Audits Locally

- **Interactive CLI audit:**
  ```bash
  python repoguard_cli.py --path samples/vulnerable_repo
  ```
- **Export standalone HTML:**
  ```bash
  python repoguard_cli.py --path . --export-html repoguard_report.html
  ```
- **Launch Web Dashboard:**
  ```bash
  python repoguard_cli.py --serve --port 8000
  ```

---

## 📋 Pull Request Requirements
- Follow PEP 8 style standards.
- Ensure all 24+ automated tests pass (`python -m pytest -v`).
- Keep code self-contained and local (zero cloud dependencies, light theme dashboard).
- Adhere to the [Code of Conduct](CODE_OF_CONDUCT.md).
