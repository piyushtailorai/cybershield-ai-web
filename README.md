# 🛡️ CyberShield AI — Live Threat Attack Simulator & Neural Defense

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-06b6d4?style=for-the-badge&logo=githubpages&logoColor=white)](https://piyushtailorai.github.io/cybershield-ai-web/)
[![Vite](https://img.shields.io/badge/Vite-8.3-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind%20CSS-v4-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)

> **Live Deployment:** [https://piyushtailorai.github.io/cybershield-ai-web/](https://piyushtailorai.github.io/cybershield-ai-web/)

---

## 🌐 Overview

**CyberShield AI** is a state-of-the-art, high-fidelity Cybersecurity Operations Center (SOC) dashboard and live adversary attack simulator. Designed with a sleek futuristic dark-mode terminal UI, CyberShield AI enables security engineers, SOC analysts, and operators to detect malicious vectors, safely detonate polymorphic exploits in micro-enclave sandboxes, stress-test defenses in real time, and monitor live enterprise telemetry.

---

## ✨ Key Features Overview

### 1. 🔍 AI-Powered Hero Threat Scanner
- **Multi-Vector Scanning**: Analyzes suspicious URLs, IPv4/IPv6 hosts, FQDN domains, and raw bytecode payloads.
- **Pre-Flight Input Validation**:
  - Rejects empty buffers (`ERR_EMPTY_PAYLOAD_BUFFER`).
  - Guards against buffer overflows exceeding 64 KB (`ERR_PAYLOAD_BUFFER_OVERFLOW`).
  - Enforces RFC-3986 URI and FQDN specifications (`ERR_MALFORMED_URI_STRUCTURE`, `ERR_MISSING_FQDN_TLD`).
  - Validates 8-bit octet boundaries on IPv4 addresses (`ERR_INVALID_IPV4_OCTET`).
  - Sanitizes Base64 bytecode and hex escape shellcode (`ERR_MALFORMED_BASE64_BYTECODE`, `ERR_CORRUPT_HEX_SHELLCODE`).
- **Interactive Scan Progression**: Live multi-step scanning animation with stage breakdown and heuristic risk grading (Score / 100).

### 2. ⚡ Live Threat Attack Simulator
- **Simulate DDoS Spike**:
  - Injects high-volume SYN/UDP packet saturation across edge nodes.
  - Elevates threat gauge to **84/100 (HIGH)**, spikes telemetry latency, activates ingress scrubbers, and logs SIEM telemetry.
- **Simulate Phishing Outbreak**:
  - Emulates an AI-voice clone and adversary SAML credential harvesting assault.
  - Elevates threat gauge to **91/100 (CRITICAL)**, revokes compromised sessions, and enforces hardware FIDO3 biometric challenges.
- **Simulate Ransomware Infiltration**:
  - Detonates polymorphic memory encryptors attempting Volume Shadow Copy wiping via `vssadmin.exe`.
  - Elevates threat gauge to **99/100 (CRITICAL)**, triggers a **14ms synthetic micro-enclave SIGKILL**, and preserves 100% of data (0 bytes encrypted).
- **One-Click Baseline Reset**: Instantly normalizes telemetry back to baseline verified state (4/100 CLEAN).

### 3. 🧪 Adversary Payload Fuzzer & Validation Chamber
- **Automated Sanitizer**: Gracefully catches corrupt, malformed, or zero-byte vectors without runtime exceptions or UI crashes.
- **One-Click Fuzzer Presets**:
  - *Clean Base64 Script* (Normal pass)
  - *Test Empty Buffer* (Triggers empty buffer validation error)
  - *Malformed Base64* (Triggers corrupt Base64 parser error)
  - *Corrupt Hex Shellcode* (Triggers hex byte validation error)
  - *Simulate Sandbox Fault* (Simulates virtual hypervisor SIGSEGV isolation failure)
- **High-Tech Diagnostic Error Banners**: Complete with exact memory RIP addresses, error codes, remediation guidance, and an **"Auto-Sanitize & Retry"** button.
- **Multi-Stage Sandbox Loading Bar**: Displays real-time progress percentages and execution stages during detonation.

### 4. 📊 Verified SOC Telemetry & 2026 Benchmarks
- **Bento Stat Grid**: Live tracked metrics across 4,200 nodes:
  - Threats Neutralized (2.4M+)
  - True-Positive Accuracy (99.98%)
  - Dynamic Neural Latency (Live ms tracker)
  - Losses Prevented ($42M+)
- **Interactive SVG Trend Line**: Visualizes monthly threat neutralization ramps with interactive hover point inspection.
- **Dynamic Circular Gauge**: Animated SVG radial threat meter updating with smooth transitions based on current threat posture.

### 5. 📜 Real-Time Security Intelligence Feed & CVE Advisories
- **Live Terminal Activity Stream**: Real-time chronological SIEM logs tagged with severity badges, timestamps, vector classifications, and filter options.
- **High-Priority Threat Advisories**: CVE monitoring stream with detailed advisory modals, severity tags, CVSS ratings, and automated mitigation playbooks.

### 6. 📱 Responsive Mobile Breakpoint Architecture
- **Dedicated Mobile Quick-Nav**: Instant-access sticky sub-navigation bar for viewports `< 768px`.
- **Adaptive Layouts**: Responsive wrapping, flexible grid columns, and mobile-first touch optimization.
- **Typography & Aesthetics**: JetBrains Mono code rendering, glowing cyber borders, pulse animations, and custom terminal scrollbars.

---

## 🛠️ Tech Stack

| Technology | Purpose |
| :--- | :--- |
| **[React 19](https://react.dev/)** | Component-driven declarative UI architecture |
| **[TypeScript 5.8](https://www.typescriptlang.org/)** | Type safety, rigorous payload interfaces, and compile-time validation |
| **[Vite 8](https://vitejs.dev/)** | Fast HMR dev server and optimized production bundling |
| **[Tailwind CSS v4](https://tailwindcss.com/)** | Utility-first cybersecurity dark-mode design system |
| **[@tailwindcss/vite](https://tailwindcss.com/)** | Vite plugin for next-generation Tailwind compilation |
| **[@google/genai](https://github.com/google-gemini/generative-ai-js)** | Google Gemini AI integration for intelligent threat heuristics |
| **[Lucide React](https://lucide.dev/)** | Cybersecurity and telemetry iconography |
| **[Material Symbols](https://fonts.google.com/icons)** | High-tech SOC status indicators and telemetry symbols |
| **[GitHub Pages](https://pages.github.com/)** | Zero-downtime static site deployment with custom repository base path |

---

## 🚀 Getting Started Locally

### Prerequisites
- [Node.js](https://nodejs.org/) (v18.0.0 or higher recommended)
- `npm` (v9.0.0 or higher)

### 1. Clone the Repository
```bash
git clone https://github.com/piyushtailorai/cybershield-ai-web.git
cd cybershield-ai-web
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment Variables (Optional)
Create a `.env.local` file in the root directory:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```

### 4. Start Development Server
```bash
npm run dev
```
Open [http://localhost:3000/](http://localhost:3000/) in your browser.

### 5. Build for Production
```bash
npm run build
```
The output will be generated in the `dist/` directory configured with the `/cybershield-ai-web/` base path for GitHub Pages.

---

## 📦 GitHub Pages Deployment

The application is pre-configured with `base: '/cybershield-ai-web/'` in [`vite.config.ts`](./vite.config.ts).

To deploy or update GitHub Pages:

### Method 1: Using `gh-pages`
```bash
npm run build
npx gh-pages -d dist
```

### Method 2: GitHub Actions Workflow
Create `.github/workflows/deploy.yml`:
```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches: [main]

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: 'pages'
  cancel-in-progress: true

jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Setup Pages
        uses: actions/configure-pages@v4

      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: './dist'

      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

---

## 📄 License

This project is licensed under the MIT License — feel free to explore, fork, and build upon CyberShield AI!

---

<div align="center">
  <sub>Built with ❤️ by Piyush Tailor • Powered by Google AI & Modern Web Technologies</sub>
</div>
