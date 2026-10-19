/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';

type ScanMode = 'url' | 'ip' | 'payload';

interface ThreatRecord {
  id: string;
  target: string;
  score: number;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'CLEAN';
  signatures: number;
  anomalies: number;
  reputation: string;
  scanTime: string;
  category: string;
}

interface AdvisoryItem {
  id: string;
  cve: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'ELEVATED';
  score: string;
  timeAgo: string;
  summary: string;
  remediation: string;
}

const SAMPLE_ADVISORIES: AdvisoryItem[] = [
  {
    id: 'ADV-1',
    cve: 'CVE-2026-8812',
    title: 'Zero-Click WebKit Memory Integrity Escape',
    severity: 'CRITICAL',
    score: '9.8',
    timeAgo: '3m ago',
    summary: 'Isolated sandbox bypass executing via malformed canvas shader buffers and WebGPU dispatchers.',
    remediation: 'Apply kernel patch CS-26.4 or activate runtime memory isolation shield.'
  },
  {
    id: 'ADV-2',
    cve: 'CVE-2026-7419',
    title: 'PhishGuard: Biometric Voice-Clone Harvester',
    severity: 'HIGH',
    score: '8.4',
    timeAgo: '12m ago',
    summary: 'Synthetic neural audio auth request targeting corporate SSO enterprise endpoints.',
    remediation: 'Enforce hardware cryptographic FIDO3 passkeys and multi-factor biometric challenge.'
  },
  {
    id: 'ADV-3',
    cve: 'CVE-2026-6104',
    title: 'Polymorphic DNS Exfiltration Beacon',
    severity: 'ELEVATED',
    score: '7.1',
    timeAgo: '28m ago',
    summary: 'Stealthy tunnel data transmission masked within standard NTP sync request frames.',
    remediation: 'Enable autonomous deep packet inspection and immediate DNS resolver sinkholing.'
  },
  {
    id: 'ADV-4',
    cve: 'CVE-2026-5520',
    title: 'OAuth Token Session Hijack Vector',
    severity: 'HIGH',
    score: '8.1',
    timeAgo: '45m ago',
    summary: 'Cross-origin token leakage triggered through misconfigured third-party iframe bindings.',
    remediation: 'Deploy strict Content-Security-Policy headers and revoke lingering bearer sessions.'
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState<ScanMode>('url');
  const [scanInput, setScanInput] = useState<string>('https://secure-login-verify-account.com/auth-token');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanStage, setScanStage] = useState<string>('');
  const [currentThreat, setCurrentThreat] = useState<ThreatRecord>({
    id: '#CX-9021',
    target: 'phishing-portal-mock.xyz',
    score: 88,
    riskLevel: 'HIGH',
    signatures: 14,
    anomalies: 3,
    reputation: '98.4%',
    scanTime: 'Just now',
    category: 'Credential Phishing Vector'
  });
  const [showAdvisoryModal, setShowAdvisoryModal] = useState<boolean>(false);
  const [selectedAdvisory, setSelectedAdvisory] = useState<AdvisoryItem | null>(null);
  const [hoveredChartPoint, setHoveredChartPoint] = useState<number | null>(null);
  const [selectedQuarter, setSelectedQuarter] = useState<number | null>(2);
  const [liveLatency, setLiveLatency] = useState<number>(14);
  const [showInfoModal, setShowInfoModal] = useState<string | null>(null);

  // Periodic latency simulation for tactical SOC feel
  useEffect(() => {
    const interval = setInterval(() => {
      setLiveLatency(Math.floor(12 + Math.random() * 5));
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleTabChange = (tab: ScanMode) => {
    setActiveTab(tab);
    if (tab === 'url') {
      setScanInput('https://secure-login-verify-account.com/auth-token');
    } else if (tab === 'ip') {
      setScanInput('194.26.29.112:8443 (Suspicious Edge Node)');
    } else {
      setScanInput('eval(atob("ZG9jdW1lbnQubG9jYXRpb249J2h0dHA6Ly9tYWxpY2lvdXMtZGVzdC5jb20nOw=="));');
    }
  };

  const handlePreset = (val: string) => {
    setScanInput(val);
  };

  const triggerScan = (customTarget?: string) => {
    const target = customTarget || scanInput;
    setIsScanning(true);
    setScanStage('Deconstructing URI & Network Vectors...');

    setTimeout(() => {
      setScanStage('Executing 140+ Isolated Neural Models...');
    }, 600);

    setTimeout(() => {
      setScanStage('Synthesizing Heuristic Security Certainty...');
    }, 1200);

    setTimeout(() => {
      setIsScanning(false);
      setScanStage('');

      // Determine realistic simulated result based on input
      const isClean = target.toLowerCase().includes('google') || target.toLowerCase().includes('github') || target.toLowerCase().includes('corp-telemetry');
      const isExtreme = target.toLowerCase().includes('ransom') || target.toLowerCase().includes('194.26');

      const newScore = isClean ? 2 : isExtreme ? 97 : 88;
      const newRisk: ThreatRecord['riskLevel'] = isClean ? 'CLEAN' : isExtreme ? 'CRITICAL' : 'HIGH';

      setCurrentThreat({
        id: `#CX-${Math.floor(1000 + Math.random() * 9000)}`,
        target: target.length > 36 ? target.substring(0, 36) + '...' : target,
        score: newScore,
        riskLevel: newRisk,
        signatures: isClean ? 0 : isExtreme ? 22 : 14,
        anomalies: isClean ? 0 : isExtreme ? 6 : 3,
        reputation: isClean ? '99.9%' : isExtreme ? '12.4%' : '98.4%',
        scanTime: 'Just now',
        category: isClean ? 'Legitimate Domain Verified' : isExtreme ? 'Command & Control Exfiltration' : 'Credential Harvest Attempt'
      });
    }, 1800);
  };

  // Circumference calculation for 40px radius circle: 2 * pi * 40 ≈ 251.2
  const maxCircumference = 251.2;
  const strokeDashoffset = maxCircumference - (maxCircumference * currentThreat.score) / 100;

  return (
    <div className="bg-[#0f131d] min-h-screen text-[#dfe2f1] flex flex-col selection:bg-[#06b6d4] selection:text-[#00424f] font-sans relative overflow-x-hidden">

      {/* Background Ambient Living Grid */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute top-10 left-1/4 w-96 h-96 rounded-full bg-[#4cd7f6]/10 blur-[130px] animate-glow" />
        <div className="absolute top-80 right-10 w-[30rem] h-[30rem] rounded-full bg-[#4edea3]/8 blur-[140px]" />
        <div className="absolute bottom-20 left-10 w-80 h-80 rounded-full bg-[#06b6d4]/10 blur-[110px]" />
        {/* Fine Circuit Pattern */}
        <div className="absolute inset-0 opacity-[0.035] bg-[radial-gradient(#4cd7f6_1px,transparent_1px)] [background-size:24px_24px]" />
      </div>

      {/* STICKY TOP NAVBAR */}
      <header className="fixed top-0 left-0 right-0 z-50 bg-[#0a0e18]/85 backdrop-blur-xl border-b border-[#3d494c]/30 shadow-[0_4px_24px_rgba(0,0,0,0.5)]">
        <div className="h-16 w-full max-w-7xl mx-auto px-4 md:px-8 flex items-center justify-between gap-4">

          {/* Logo & Brand */}
          <div className="flex items-center gap-6">
            <a href="#" className="flex items-center gap-2.5 group">
              <img
                src="https://lh3.googleusercontent.com/aida/AEtjO1WLUEO_A7ZbhujLj0vY4BjmMgXjGJ8Jaz-fYTEQ3R45lY5ofNvP3_jc_chf-h6n6YbrdyB3Q4v6kgOaUjaaJO71u4mOnxjqcVGS_ARUYK0at0Qz_n4ezXQ9SAWrzNpgMBavvpEycRa4wNpJKEuRqPsZIhIY1ldOCHmjMgBA3ozhB1nm4LpqP80_9jT12e7JbXnDGjU7bPNEufMhLl_9r32djPbhjUiZ979Qlf8zl_hP4zq44YV6yuh3Y-k"
                alt="CyberShield AI Logo"
                className="h-8 w-auto object-contain transition-transform group-hover:scale-105"
              />
              <span className="font-bold text-lg text-[#dfe2f1] tracking-tight uppercase">
                CyberShield AI
              </span>
              <span className="text-[10px] text-[#4edea3] bg-[#4edea3]/10 px-2 py-0.5 rounded-full font-mono font-semibold ml-2 border border-[#4edea3]/30 shadow-inner">
                ● SYSTEM ONLINE (24/7 CLOUD)
              </span>
            </a>

            {/* Menu Links */}
            <nav className="hidden md:flex items-center gap-1.5 font-mono text-xs">
              <a
                href="#scanner"
                className="px-3 py-1.5 rounded-lg bg-[#262a35] text-[#4cd7f6] font-semibold transition-colors"
              >
                Scanner
              </a>
              <a
                href="#threat-intel"
                className="px-3 py-1.5 rounded-lg text-[#bcc9cd] hover:bg-[#1c1f2a] hover:text-[#dfe2f1] transition-colors"
              >
                Threat Intel
              </a>
              <a
                href="#roadmap"
                className="px-3 py-1.5 rounded-lg text-[#bcc9cd] hover:bg-[#1c1f2a] hover:text-[#dfe2f1] transition-colors"
              >
                Roadmap
              </a>
            </nav>
          </div>

          {/* Right Controls */}
          <div className="flex items-center gap-3">
            {/* Real-time Status Badge */}
            <div className="hidden lg:flex items-center gap-2 px-3 py-1 rounded-full bg-[#171b26] border border-[#3d494c]/30 shadow-inner">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#4edea3] opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[#4edea3]" />
              </span>
              <span className="font-mono text-[10px] text-[#4edea3] font-semibold tracking-wider uppercase">
                SYSTEM NORMAL // LATENCY {liveLatency}ms
              </span>
            </div>

            {/* Glowing Run Scan Button */}
            <button
              type="button"
              onClick={() => triggerScan()}
              disabled={isScanning}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#06b6d4] text-[#00424f] font-mono text-xs font-bold shadow-[0_0_18px_rgba(6,182,212,0.5)] hover:bg-[#4cd7f6] hover:shadow-[0_0_26px_rgba(6,182,212,0.7)] active:scale-95 transition-all cursor-pointer disabled:opacity-70"
            >
              <span className={`material-symbols-outlined text-[18px] ${isScanning ? 'animate-spin' : ''}`}>
                radar
              </span>
              <span>{isScanning ? 'Scanning...' : 'Run Scan'}</span>
            </button>

            {/* Profile Avatar Icon */}
            <button
              type="button"
              onClick={() => setShowInfoModal('user')}
              className="w-8 h-8 rounded-full bg-[#4cd7f6] flex items-center justify-center shrink-0 hover:ring-2 hover:ring-[#4cd7f6]/50 transition-all cursor-pointer"
              title="SOC Analyst Terminal ID"
            >
              <span className="material-symbols-outlined text-[#003640] text-[18px]">
                person
              </span>
            </button>
          </div>
        </div>
      </header>

      {/* MAIN CONTENT AREA */}
      <main className="w-full pt-20 flex-1 flex flex-col relative z-10">
        <div className="w-full max-w-7xl mx-auto px-4 md:px-8 flex flex-col gap-10 py-6 md:py-10">

          {/* 1. HERO SCANNING CONSOLE */}
          <section id="scanner" className="flex flex-col items-center text-center relative w-full pt-4">

            {/* High-tech Classification Overline */}
            <div className="flex items-center gap-2 px-3.5 py-1 rounded-full bg-[#262a35] border border-[#3d494c]/40 shadow-inner">
              <span className="inline-block w-2 h-2 rounded-full bg-[#4cd7f6] animate-pulse" />
              <span className="font-mono text-[10px] text-[#4cd7f6] tracking-widest uppercase font-semibold">
                NEURAL LINK INTELLIGENCE // DEPLOYED V4.9
              </span>
            </div>

            {/* Main Headline & Subtitle */}
            <div className="max-w-3xl flex flex-col gap-2 mt-4">
              <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold text-[#dfe2f1] tracking-tight leading-tight">
                AI-Powered Threat Detection <br className="hidden sm:inline" />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#4cd7f6] via-[#06b6d4] to-[#4edea3]">
                  & Link Defense
                </span>
              </h1>
              <p className="text-sm md:text-base text-[#bcc9cd] max-w-2xl mx-auto mt-1">
                Analyze suspicious URLs, domain vectors, and raw payload code across 140+ neural security models in real time.
              </p>
            </div>

            {/* Mode Switcher Tabs */}
            <div className="mt-6 flex items-center bg-[#0a0e18] p-1 rounded-xl border border-[#3d494c]/30 shadow-inner gap-1">
              <button
                type="button"
                onClick={() => handleTabChange('url')}
                className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg font-mono text-xs font-semibold transition-all cursor-pointer ${
                  activeTab === 'url'
                    ? 'text-[#00424f] bg-[#06b6d4] shadow-[0_0_12px_rgba(6,182,212,0.5)]'
                    : 'text-[#bcc9cd] hover:text-[#dfe2f1] hover:bg-[#1c1f2a]'
                }`}
              >
                <span className="material-symbols-outlined text-[16px]">link</span>
                <span>URL Scan</span>
              </button>

              <button
                type="button"
                onClick={() => handleTabChange('ip')}
                className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg font-mono text-xs font-semibold transition-all cursor-pointer ${
                  activeTab === 'ip'
                    ? 'text-[#00424f] bg-[#06b6d4] shadow-[0_0_12px_rgba(6,182,212,0.5)]'
                    : 'text-[#bcc9cd] hover:text-[#dfe2f1] hover:bg-[#1c1f2a]'
                }`}
              >
                <span className="material-symbols-outlined text-[16px]">dns</span>
                <span>IP / Domain</span>
              </button>

              <button
                type="button"
                onClick={() => handleTabChange('payload')}
                className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg font-mono text-xs font-semibold transition-all cursor-pointer ${
                  activeTab === 'payload'
                    ? 'text-[#00424f] bg-[#06b6d4] shadow-[0_0_12px_rgba(6,182,212,0.5)]'
                    : 'text-[#bcc9cd] hover:text-[#dfe2f1] hover:bg-[#1c1f2a]'
                }`}
              >
                <span className="material-symbols-outlined text-[16px]">code</span>
                <span>Raw Payload / Code</span>
              </button>
            </div>

            {/* High-Tech Input Console */}
            <div className="w-full max-w-4xl mt-4 bg-[#171b26]/90 backdrop-blur-xl rounded-xl p-3 md:p-4 border border-[#3d494c]/40 shadow-[0_20px_50px_rgba(0,0,0,0.7),0_0_30px_rgba(6,182,212,0.12)]">
              <div className="relative flex flex-col md:flex-row items-stretch gap-2 bg-[#0a0e18] rounded-lg p-2 border border-[#3d494c]/30 shadow-inner">
                <div className="flex items-center gap-2 px-2 flex-1 min-w-0">
                  <span className="material-symbols-outlined text-[#4cd7f6] text-[20px] shrink-0">
                    shield_lock
                  </span>
                  <span className="font-mono text-sm text-[#4cd7f6] font-bold select-none">&gt;</span>
                  <input
                    type="text"
                    value={scanInput}
                    onChange={(e) => setScanInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && triggerScan()}
                    placeholder={
                      activeTab === 'url'
                        ? 'Enter suspicious URL (e.g. https://secure-login-verify-account.com/auth)...'
                        : activeTab === 'ip'
                        ? 'Enter IP address or domain (e.g. 194.26.29.112:8443)...'
                        : 'Paste payload string or script snippet for neural sandboxing...'
                    }
                    className="w-full bg-transparent text-[#dfe2f1] placeholder:text-[#869397] font-mono text-xs md:text-sm focus:outline-none min-w-0 py-1"
                  />
                  {scanInput && (
                    <button
                      type="button"
                      onClick={() => setScanInput('')}
                      className="text-[#869397] hover:text-[#dfe2f1] text-xs font-mono px-1 cursor-pointer"
                    >
                      Clear
                    </button>
                  )}
                </div>

                <div className="flex items-center gap-2 shrink-0 self-end md:self-auto w-full md:w-auto">
                  <button
                    type="button"
                    onClick={() => triggerScan()}
                    disabled={isScanning}
                    className="w-full md:w-auto flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg bg-gradient-to-r from-[#06b6d4] to-[#4edea3] text-[#00424f] font-mono text-xs md:text-sm font-bold shadow-[0_0_20px_rgba(6,182,212,0.4)] hover:shadow-[0_0_28px_rgba(78,222,163,0.6)] active:scale-95 transition-all cursor-pointer disabled:opacity-75"
                  >
                    <span className={`material-symbols-outlined text-[18px] ${isScanning ? 'animate-spin' : ''}`}>
                      radar
                    </span>
                    <span>{isScanning ? 'Analyzing...' : 'Scan Now'}</span>
                  </button>
                </div>
              </div>

              {/* Live Scan Status Indicator */}
              {isScanning && (
                <div className="mt-3 py-2 px-3 bg-[#0a0e18]/80 rounded-lg border border-[#06b6d4]/40 flex items-center justify-between font-mono text-xs text-[#4cd7f6] animate-pulse">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#4cd7f6] animate-ping" />
                    <span>{scanStage}</span>
                  </div>
                  <span className="text-[#4edea3]">HEURISTIC ENGINE 4.1</span>
                </div>
              )}

              {/* Presets & Response Time */}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-3 px-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-mono text-[10px] text-[#869397] uppercase tracking-wider">Presets:</span>
                  <button
                    type="button"
                    onClick={() => handlePreset('https://auth-session-bank-renew.com/token-update')}
                    className="px-2.5 py-0.5 rounded bg-[#1c1f2a] text-[#bcc9cd] hover:text-[#4cd7f6] hover:bg-[#262a35] font-mono text-[11px] transition-colors cursor-pointer"
                  >
                    Deep Heuristic
                  </button>
                  <button
                    type="button"
                    onClick={() => handlePreset('194.26.29.112:8443 (Suspicious Edge Node)')}
                    className="px-2.5 py-0.5 rounded bg-[#1c1f2a] text-[#bcc9cd] hover:text-[#4cd7f6] hover:bg-[#262a35] font-mono text-[11px] transition-colors cursor-pointer"
                  >
                    Zero-Day Sandbox
                  </button>
                  <button
                    type="button"
                    onClick={() => handlePreset('ssl://api-gateway.corp-telemetry.io')}
                    className="px-2.5 py-0.5 rounded bg-[#1c1f2a] text-[#bcc9cd] hover:text-[#4cd7f6] hover:bg-[#262a35] font-mono text-[11px] transition-colors cursor-pointer"
                  >
                    SSL / WHOIS
                  </button>
                </div>

                <div className="flex items-center gap-1 font-mono text-[11px] text-[#4edea3]">
                  <span className="material-symbols-outlined text-[14px]">bolt</span>
                  <span>Cluster Response: 19ms</span>
                </div>
              </div>
            </div>

            {/* Recent Target Fast-Audit Pill */}
            <div className="mt-4 flex flex-wrap items-center justify-center gap-2 text-center">
              <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-[#171b26] border border-[#3d494c]/30 shadow-sm">
                <span className="font-mono text-xs text-[#bcc9cd]">Last scanned:</span>
                <span className="font-mono text-xs text-[#4cd7f6] font-medium">{currentThreat.target}</span>
                <span className={`inline-flex items-center px-2 py-0.5 rounded font-mono text-[11px] font-bold ${
                  currentThreat.riskLevel === 'CLEAN'
                    ? 'bg-[#4edea3]/20 text-[#4edea3]'
                    : currentThreat.riskLevel === 'CRITICAL'
                    ? 'bg-[#ff7f8b]/20 text-[#ff7f8b]'
                    : 'bg-[#ff7f8b]/20 text-[#ffb4ab]'
                }`}>
                  Threat: {currentThreat.score}/100 {currentThreat.riskLevel}
                </span>
                <a href="#card-threat" className="font-mono text-xs text-[#4cd7f6] hover:underline ml-1">
                  Quick view →
                </a>
              </div>
            </div>
          </section>

          {/* 2. MIDDLE SECTION: THREE TELEMETRY PANELS (GRID) */}
          <section id="threat-intel" className="grid grid-cols-1 lg:grid-cols-3 gap-6 w-full">

            {/* CARD 1: THREAT SCORE & MALICIOUS TELEMETRY */}
            <div
              id="card-threat"
              className="flex flex-col bg-[#171b26]/90 backdrop-blur-xl p-5 md:p-6 rounded-xl border border-[#3d494c]/30 shadow-[0_15px_35px_rgba(0,0,0,0.5)] justify-between relative overflow-hidden group"
            >
              <div className="absolute -top-12 -right-12 w-36 h-36 rounded-full bg-[#ff7f8b]/10 blur-[50px] pointer-events-none" />

              <div>
                {/* Header */}
                <div className="flex items-center justify-between pb-3">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#ff7f8b] shadow-[0_0_8px_#ff7f8b]" />
                    <span className="font-mono text-[10px] text-[#bcc9cd] uppercase tracking-wider font-semibold">
                      DIAGNOSTIC MATRIX
                    </span>
                  </div>
                  <span className="font-mono text-[11px] text-[#869397]">ENGINE 4.1-HEURISTIC</span>
                </div>

                <h3 className="text-lg font-bold text-[#dfe2f1]">Target Threat Assessment</h3>
                <p className="text-xs text-[#bcc9cd] mt-0.5">Aggregated neural certainty index for active target</p>

                {/* Circular Gauge Visualization */}
                <div className="my-5 flex flex-col items-center justify-center">
                  <div className="relative w-40 h-40 flex items-center justify-center">
                    <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                      {/* Track */}
                      <circle
                        cx="50"
                        cy="50"
                        r="40"
                        fill="transparent"
                        stroke="#1c1f2a"
                        strokeWidth="8"
                      />
                      {/* Active Ring Indicator */}
                      <circle
                        cx="50"
                        cy="50"
                        r="40"
                        fill="transparent"
                        stroke={currentThreat.score > 70 ? '#06b6d4' : currentThreat.score > 30 ? '#ffb4ab' : '#4edea3'}
                        strokeWidth="8"
                        strokeDasharray={maxCircumference}
                        strokeDashoffset={strokeDashoffset}
                        strokeLinecap="round"
                        className="transition-all duration-1000 ease-out"
                      />
                      {/* Inner Overlay Ring */}
                      <circle
                        cx="50"
                        cy="50"
                        r="32"
                        fill="transparent"
                        stroke="#4edea3"
                        strokeOpacity="0.4"
                        strokeWidth="3"
                        strokeDasharray="201"
                        strokeDashoffset="60"
                        strokeLinecap="round"
                      />
                    </svg>

                    {/* Inside Content */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                      <span className="text-4xl font-extrabold text-[#dfe2f1] tracking-tighter leading-none">
                        {currentThreat.score}
                      </span>
                      <span className="font-mono text-[11px] text-[#bcc9cd] font-medium mt-1">/ 100 MAX</span>
                    </div>
                  </div>

                  <div className={`mt-2 px-3 py-1 rounded-full font-mono text-[11px] font-semibold tracking-wider ${
                    currentThreat.riskLevel === 'CLEAN'
                      ? 'bg-[#4edea3]/20 text-[#4edea3]'
                      : 'bg-[#ff7f8b]/20 text-[#ff7f8b]'
                  }`}>
                    {currentThreat.riskLevel === 'CLEAN' ? 'ALL THREATS ABSENT // VERIFIED' : 'HIGH RISK MITIGATED'}
                  </div>
                </div>

                {/* Breakdown List */}
                <div className="space-y-1.5 pt-1">
                  <div className="flex items-center justify-between p-2 rounded bg-[#1c1f2a]/70 font-mono text-xs">
                    <span className="text-[#bcc9cd] flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-[16px] text-[#ffb2b7]">warning</span>
                      Malicious Signatures
                    </span>
                    <span className="text-[#ffb2b7] font-bold">{currentThreat.signatures} Confirmed</span>
                  </div>

                  <div className="flex items-center justify-between p-2 rounded bg-[#1c1f2a]/70 font-mono text-xs">
                    <span className="text-[#bcc9cd] flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-[16px] text-[#4cd7f6]">bug_report</span>
                      Sandbox Anomalies
                    </span>
                    <span className="text-[#4cd7f6] font-bold">{currentThreat.anomalies} Active Hooks</span>
                  </div>

                  <div className="flex items-center justify-between p-2 rounded bg-[#1c1f2a]/70 font-mono text-xs">
                    <span className="text-[#bcc9cd] flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-[16px] text-[#4edea3]">verified_user</span>
                      Reputation Integrity
                    </span>
                    <span className="text-[#4edea3] font-bold">{currentThreat.reputation} Baseline</span>
                  </div>
                </div>
              </div>

              {/* Card Footer */}
              <div className="pt-4 mt-3 border-t border-[#3d494c]/20 flex items-center justify-between text-[#bcc9cd] font-mono text-xs">
                <span className="flex items-center gap-1.5">
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#4edea3]" />
                  Real-time heuristic stream
                </span>
                <span className="text-[#4cd7f6] font-bold">{currentThreat.id}</span>
              </div>
            </div>

            {/* CARD 2: VERIFIED TELEMETRY (2026 METRICS & CHART) */}
            <div className="flex flex-col bg-[#171b26]/90 backdrop-blur-xl p-5 md:p-6 rounded-xl border border-[#3d494c]/30 shadow-[0_15px_35px_rgba(0,0,0,0.5)] justify-between relative overflow-hidden">
              <div>
                {/* Header */}
                <div className="flex items-center justify-between pb-3">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#4cd7f6] shadow-[0_0_8px_#4cd7f6]" />
                    <span className="font-mono text-[10px] text-[#4cd7f6] uppercase tracking-wider font-semibold">
                      2026 GLOBAL BENCHMARKS
                    </span>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-[#262a35] text-[#bcc9cd] font-mono text-[11px]">
                    Q1 AUDIT
                  </span>
                </div>

                <h3 className="text-lg font-bold text-[#dfe2f1]">Enterprise Velocity Metrics</h3>
                <p className="text-xs text-[#bcc9cd] mt-0.5">
                  Real-time throughput validated across 4,200 deployed corporate nodes
                </p>

                {/* 4-Stat Bento Grid */}
                <div className="grid grid-cols-2 gap-2.5 my-4">
                  <div className="bg-[#1c1f2a] p-3 rounded-lg flex flex-col justify-center border border-[#3d494c]/20">
                    <span className="text-2xl font-bold text-[#4cd7f6] leading-tight font-mono">4.2M+</span>
                    <span className="font-mono text-[11px] text-[#bcc9cd] mt-0.5">Threats Neutralized</span>
                  </div>

                  <div className="bg-[#1c1f2a] p-3 rounded-lg flex flex-col justify-center border border-[#3d494c]/20">
                    <span className="text-2xl font-bold text-[#4edea3] leading-tight font-mono">99.98%</span>
                    <span className="font-mono text-[11px] text-[#bcc9cd] mt-0.5">True-Positive Accuracy</span>
                  </div>

                  <div className="bg-[#1c1f2a] p-3 rounded-lg flex flex-col justify-center border border-[#3d494c]/20">
                    <span className="text-2xl font-bold text-[#dfe2f1] leading-tight font-mono">&lt; 42ms</span>
                    <span className="font-mono text-[11px] text-[#bcc9cd] mt-0.5">Average Neural Latency</span>
                  </div>

                  <div className="bg-[#1c1f2a] p-3 rounded-lg flex flex-col justify-center border border-[#3d494c]/20">
                    <span className="text-2xl font-bold text-[#4edea3] leading-tight font-mono">$18.4M</span>
                    <span className="font-mono text-[11px] text-[#bcc9cd] mt-0.5">Losses Prevented</span>
                  </div>
                </div>

                {/* Trend Line Chart Component */}
                <div className="bg-[#1c1f2a]/70 p-3 rounded-lg border border-[#3d494c]/20">
                  <div className="flex items-center justify-between pb-1">
                    <span className="font-mono text-[10px] text-[#bcc9cd] uppercase">
                      Threat Neutralization Ramp (2026)
                    </span>
                    <span className="font-mono text-xs text-[#4edea3] font-semibold">+34.8% MoM</span>
                  </div>

                  <div className="h-20 w-full flex items-end relative">
                    <svg className="w-full h-full overflow-visible" preserveAspectRatio="none" viewBox="0 0 280 60">
                      <defs>
                        <linearGradient id="gradientTrend" x1="0%" y1="0%" x2="0%" y2="100%">
                          <stop offset="0%" stopColor="#4cd7f6" stopOpacity="0.35" />
                          <stop offset="100%" stopColor="#4cd7f6" stopOpacity="0.0" />
                        </linearGradient>
                      </defs>
                      <path
                        d="M0,52 Q40,48 70,35 T140,32 T210,18 T280,6 L280,60 L0,60 Z"
                        fill="url(#gradientTrend)"
                      />
                      <path
                        d="M0,52 Q40,48 70,35 T140,32 T210,18 T280,6"
                        fill="none"
                        stroke="#4cd7f6"
                        strokeLinecap="round"
                        strokeWidth="2.5"
                      />

                      {/* Interactive Key Point Dots */}
                      <circle
                        cx="70"
                        cy="35"
                        r={hoveredChartPoint === 1 ? 5 : 3.5}
                        className="fill-[#4cd7f6] cursor-pointer transition-all"
                        onMouseEnter={() => setHoveredChartPoint(1)}
                        onMouseLeave={() => setHoveredChartPoint(null)}
                      />
                      <circle
                        cx="140"
                        cy="32"
                        r={hoveredChartPoint === 2 ? 5 : 3.5}
                        className="fill-[#4cd7f6] cursor-pointer transition-all"
                        onMouseEnter={() => setHoveredChartPoint(2)}
                        onMouseLeave={() => setHoveredChartPoint(null)}
                      />
                      <circle
                        cx="210"
                        cy="18"
                        r={hoveredChartPoint === 3 ? 5 : 3.5}
                        className="fill-[#4cd7f6] cursor-pointer transition-all"
                        onMouseEnter={() => setHoveredChartPoint(3)}
                        onMouseLeave={() => setHoveredChartPoint(null)}
                      />
                      <circle
                        cx="280"
                        cy="6"
                        r={hoveredChartPoint === 4 ? 6 : 4}
                        className="fill-[#4edea3] shadow-[0_0_10px_#4edea3] cursor-pointer transition-all"
                        onMouseEnter={() => setHoveredChartPoint(4)}
                        onMouseLeave={() => setHoveredChartPoint(null)}
                      />
                    </svg>

                    {hoveredChartPoint && (
                      <div className="absolute top-1 right-2 px-2 py-0.5 rounded bg-[#0a0e18] border border-[#4cd7f6]/40 font-mono text-[10px] text-[#4cd7f6]">
                        {hoveredChartPoint === 1 && 'Jan: 820K attacks stopped'}
                        {hoveredChartPoint === 2 && 'Feb: 1.15M attacks stopped'}
                        {hoveredChartPoint === 3 && 'Mar: 1.84M attacks stopped'}
                        {hoveredChartPoint === 4 && 'Apr (Proj): 2.40M attacks'}
                      </div>
                    )}
                  </div>

                  <div className="flex justify-between pt-1 font-mono text-[10px] text-[#869397]">
                    <span>JAN</span>
                    <span>FEB</span>
                    <span>MAR</span>
                    <span className="text-[#4cd7f6] font-semibold">APR (PROJ)</span>
                  </div>
                </div>
              </div>

              {/* Card Footer */}
              <div className="pt-4 mt-3 border-t border-[#3d494c]/20 flex items-center justify-between text-[#bcc9cd] font-mono text-xs">
                <span>Certified SOC-2 Type II</span>
                <span className="text-[#4edea3] font-semibold">SLAs 100% MET</span>
              </div>
            </div>

            {/* CARD 3: LIVE VULNERABILITY ALERTS & AI INTEL FEED */}
            <div className="flex flex-col bg-[#171b26]/90 backdrop-blur-xl p-5 md:p-6 rounded-xl border border-[#3d494c]/30 shadow-[0_15px_35px_rgba(0,0,0,0.5)] justify-between relative overflow-hidden">
              <div>
                {/* Header with streaming ping */}
                <div className="flex items-center justify-between pb-3">
                  <div className="flex items-center gap-2">
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#4edea3] opacity-80" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-[#4edea3]" />
                    </span>
                    <span className="font-mono text-[10px] text-[#4edea3] uppercase tracking-widest font-semibold">
                      STREAMING LIVE
                    </span>
                  </div>
                  <span className="font-mono text-[11px] text-[#869397]">GLOBAL SOC FEED</span>
                </div>

                <h3 className="text-lg font-bold text-[#dfe2f1]">Vulnerability Intercepts</h3>
                <p className="text-xs text-[#bcc9cd] mt-0.5">
                  Autonomous intelligence harvested by global sensory honeynets
                </p>

                {/* Real-Time Feed Items */}
                <div className="space-y-2.5 my-3.5">
                  {SAMPLE_ADVISORIES.slice(0, 3).map((advisory) => (
                    <button
                      key={advisory.id}
                      type="button"
                      onClick={() => {
                        setSelectedAdvisory(advisory);
                        setShowAdvisoryModal(true);
                      }}
                      className="w-full text-left p-2.5 rounded-lg bg-[#1c1f2a]/70 hover:bg-[#1c1f2a] border border-[#3d494c]/20 hover:border-[#4cd7f6]/40 transition-all flex flex-col gap-1 cursor-pointer group"
                    >
                      <div className="flex items-center justify-between">
                        <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
                          advisory.severity === 'CRITICAL'
                            ? 'bg-[#ff7f8b]/20 text-[#ffb4ab]'
                            : advisory.severity === 'HIGH'
                            ? 'bg-[#ff7f8b]/15 text-[#ff7f8b]'
                            : 'bg-[#4cd7f6]/20 text-[#4cd7f6]'
                        }`}>
                          {advisory.severity} {advisory.score}
                        </span>
                        <span className="font-mono text-[10px] text-[#869397]">{advisory.timeAgo}</span>
                      </div>
                      <h4 className="font-mono text-xs text-[#dfe2f1] font-semibold truncate group-hover:text-[#4cd7f6] transition-colors">
                        {advisory.cve} - {advisory.title}
                      </h4>
                      <p className="text-[11px] text-[#bcc9cd] line-clamp-1">
                        {advisory.summary}
                      </p>
                    </button>
                  ))}
                </div>
              </div>

              {/* Card Footer Action */}
              <div className="pt-3 border-t border-[#3d494c]/20">
                <button
                  type="button"
                  onClick={() => setShowAdvisoryModal(true)}
                  className="w-full inline-flex items-center justify-between font-mono text-xs text-[#4cd7f6] hover:text-[#4edea3] transition-colors group cursor-pointer"
                >
                  <span>Explore All 42 Active Intel Advisories</span>
                  <span className="material-symbols-outlined text-[16px] group-hover:translate-x-1 transition-transform">
                    arrow_forward
                  </span>
                </button>
              </div>
            </div>

          </section>

          {/* 3. BOTTOM SECTION: 4-QUARTER PRODUCT ROADMAP TIMELINE */}
          <section
            id="roadmap"
            className="flex flex-col w-full bg-[#171b26]/75 backdrop-blur-xl p-5 md:p-8 rounded-xl border border-[#3d494c]/30 shadow-[0_15px_40px_rgba(0,0,0,0.6)]"
          >
            {/* Section Header */}
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-6">
              <div>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#4edea3]" />
                  <span className="font-mono text-[10px] text-[#4edea3] uppercase tracking-widest font-semibold">
                    STRATEGIC ARCHITECTURE
                  </span>
                </div>
                <h2 className="text-2xl md:text-3xl text-[#dfe2f1] font-bold mt-1 tracking-tight">
                  CyberShield 2026 Innovation Roadmap
                </h2>
                <p className="text-xs md:text-sm text-[#bcc9cd] max-w-xl mt-1">
                  Our quarterly release milestones for next-generation autonomous cyber defense and cryptographic trust.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-[#bcc9cd]">Version 2026.4 Target Track</span>
              </div>
            </div>

            {/* Horizontal Continuous Timeline Ribbon (Desktop 4-Col, Mobile Stacked) */}
            <div className="relative grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">

              {/* Connecting Track Line (Desktop only) */}
              <div className="hidden lg:block absolute top-10 left-8 right-8 h-0.5 bg-[#262a35] pointer-events-none">
                <div className="h-full bg-gradient-to-r from-[#4edea3] via-[#06b6d4] to-[#262a35] w-1/2" />
              </div>

              {/* QUARTER 1: COMPLETED */}
              <div
                onClick={() => setSelectedQuarter(1)}
                className={`relative flex flex-col p-4 rounded-xl transition-all cursor-pointer border ${
                  selectedQuarter === 1
                    ? 'bg-[#262a35] border-[#4edea3]/50 shadow-[0_0_20px_rgba(78,222,163,0.15)]'
                    : 'bg-[#1c1f2a]/80 border-[#3d494c]/20 hover:bg-[#1c1f2a]'
                }`}
              >
                <div className="flex items-center justify-between pb-2">
                  <span className="text-lg font-bold text-[#dfe2f1] font-mono">Q1 2026</span>
                  <span className="px-2.5 py-0.5 rounded-full bg-[#4edea3]/15 text-[#4edea3] font-mono text-[11px] font-semibold flex items-center gap-1">
                    <span className="material-symbols-outlined text-[14px]">check_circle</span>
                    LIVE IN PRODUCTION
                  </span>
                </div>

                <h4 className="text-base text-[#4cd7f6] font-semibold mt-1">
                  Neural URL & Payload Sandbox
                </h4>
                <p className="text-xs text-[#bcc9cd] mt-1">
                  High-concurrency isolated execution chamber executing zero-day telemetry.
                </p>

                <ul className="mt-3.5 space-y-1.5 text-[#bcc9cd] font-mono text-xs">
                  <li className="flex items-start gap-1.5">
                    <span className="material-symbols-outlined text-[#4edea3] text-[16px] shrink-0">done</span>
                    <span>Sub-50ms heuristic neural parsing</span>
                  </li>
                  <li className="flex items-start gap-1.5">
                    <span className="material-symbols-outlined text-[#4edea3] text-[16px] shrink-0">done</span>
                    <span>Automated honeypot redirects</span>
                  </li>
                  <li className="flex items-start gap-1.5">
                    <span className="material-symbols-outlined text-[#4edea3] text-[16px] shrink-0">done</span>
                    <span>Browser extension telemetry v2.4</span>
                  </li>
                </ul>

                <div className="mt-4 pt-2.5 border-t border-[#3d494c]/20 flex items-center justify-between font-mono text-[11px] text-[#869397]">
                  <span>Delivered Jan 18</span>
                  <span className="text-[#4edea3] font-bold">100% Rollout</span>
                </div>
              </div>

              {/* QUARTER 2: CURRENT SPRINT (ACTIVE) */}
              <div
                onClick={() => setSelectedQuarter(2)}
                className={`relative flex flex-col p-4 rounded-xl transition-all cursor-pointer border ${
                  selectedQuarter === 2
                    ? 'bg-[#262a35] border-[#4cd7f6] shadow-[0_0_24px_rgba(6,182,212,0.25)] ring-1 ring-[#4cd7f6]/40'
                    : 'bg-[#262a35]/90 border-[#4cd7f6]/40 hover:bg-[#262a35]'
                }`}
              >
                <div className="flex items-center justify-between pb-2">
                  <span className="text-lg font-bold text-[#dfe2f1] font-mono">Q2 2026</span>
                  <span className="px-2.5 py-0.5 rounded-full bg-[#06b6d4]/20 text-[#4cd7f6] font-mono text-[11px] font-bold flex items-center gap-1 animate-pulse">
                    <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#4cd7f6]" />
                    IN PROGRESS // 82%
                  </span>
                </div>

                <h4 className="text-base text-[#4cd7f6] font-semibold mt-1">
                  Autonomous Threat Neutralization
                </h4>
                <p className="text-xs text-[#bcc9cd] mt-1">
                  Closed-loop mitigation triggers taking sub-second defensive actions without human intervention.
                </p>

                <ul className="mt-3.5 space-y-1.5 text-[#bcc9cd] font-mono text-xs">
                  <li className="flex items-start gap-1.5">
                    <span className="material-symbols-outlined text-[#4cd7f6] text-[16px] shrink-0">sync</span>
                    <span>1-Click automated DNS sinkholing</span>
                  </li>
                  <li className="flex items-start gap-1.5">
                    <span className="material-symbols-outlined text-[#4cd7f6] text-[16px] shrink-0">sync</span>
                    <span>AI-assisted firewall rule synthesis</span>
                  </li>
                  <li className="flex items-start gap-1.5">
                    <span className="material-symbols-outlined text-[#4cd7f6] text-[16px] shrink-0">sync</span>
                    <span>Direct SIEM Webhook orchestration</span>
                  </li>
                </ul>

                <div className="mt-4 pt-2.5 border-t border-[#3d494c]/20 flex items-center justify-between font-mono text-[11px] text-[#869397]">
                  <span>Target: May 30</span>
                  <span className="text-[#4cd7f6] font-bold">Active Sprint 14</span>
                </div>
              </div>

              {/* QUARTER 3: UPCOMING */}
              <div
                onClick={() => setSelectedQuarter(3)}
                className={`relative flex flex-col p-4 rounded-xl transition-all cursor-pointer border ${
                  selectedQuarter === 3
                    ? 'bg-[#262a35] border-[#ffb2b7]/50 shadow-[0_0_20px_rgba(255,178,183,0.15)]'
                    : 'bg-[#1c1f2a]/80 border-[#3d494c]/20 hover:bg-[#1c1f2a]'
                }`}
              >
                <div className="flex items-center justify-between pb-2">
                  <span className="text-lg font-bold text-[#dfe2f1] font-mono">Q3 2026</span>
                  <span className="px-2.5 py-0.5 rounded-full bg-[#313540] text-[#ffb2b7] font-mono text-[11px] font-semibold flex items-center gap-1">
                    <span className="material-symbols-outlined text-[14px]">schedule</span>
                    PLANNED - TESTING
                  </span>
                </div>

                <h4 className="text-base text-[#dfe2f1] font-semibold mt-1">
                  Multi-Agent Deception Grids
                </h4>
                <p className="text-xs text-[#bcc9cd] mt-1">
                  Dynamic ghost infrastructure that misleads adversary probes and maps intent.
                </p>

                <ul className="mt-3.5 space-y-1.5 text-[#bcc9cd] font-mono text-xs">
                  <li className="flex items-start gap-1.5">
                    <span className="material-symbols-outlined text-[#869397] text-[16px] shrink-0">radio_button_unchecked</span>
                    <span>Decoy backend microservices</span>
                  </li>
                  <li className="flex items-start gap-1.5">
                    <span className="material-symbols-outlined text-[#869397] text-[16px] shrink-0">radio_button_unchecked</span>
                    <span>Attacker behavioral telemetry</span>
                  </li>
                  <li className="flex items-start gap-1.5">
                    <span className="material-symbols-outlined text-[#869397] text-[16px] shrink-0">radio_button_unchecked</span>
                    <span>Synthetic credentials honey-token</span>
                  </li>
                </ul>

                <div className="mt-4 pt-2.5 border-t border-[#3d494c]/20 flex items-center justify-between font-mono text-[11px] text-[#869397]">
                  <span>Target: Aug 2026</span>
                  <span>Architecture Lab</span>
                </div>
              </div>

              {/* QUARTER 4: FUTURE HORIZON */}
              <div
                onClick={() => setSelectedQuarter(4)}
                className={`relative flex flex-col p-4 rounded-xl transition-all cursor-pointer border ${
                  selectedQuarter === 4
                    ? 'bg-[#262a35] border-[#4cd7f6]/50 shadow-[0_0_20px_rgba(78,222,163,0.15)]'
                    : 'bg-[#1c1f2a]/60 border-[#3d494c]/20 hover:bg-[#1c1f2a]'
                }`}
              >
                <div className="flex items-center justify-between pb-2">
                  <span className="text-lg font-bold text-[#dfe2f1] font-mono">Q4 2026</span>
                  <span className="px-2.5 py-0.5 rounded-full bg-[#313540] text-[#869397] font-mono text-[11px] font-semibold flex items-center gap-1">
                    <span className="material-symbols-outlined text-[14px]">lightbulb</span>
                    CONCEPT PHASE
                  </span>
                </div>

                <h4 className="text-base text-[#dfe2f1] font-semibold mt-1">
                  Quantum-Resistant Mesh
                </h4>
                <p className="text-xs text-[#bcc9cd] mt-1">
                  Post-quantum zero-trust envelope protecting critical distributed consensus nodes.
                </p>

                <ul className="mt-3.5 space-y-1.5 text-[#bcc9cd] font-mono text-xs">
                  <li className="flex items-start gap-1.5">
                    <span className="material-symbols-outlined text-[#869397] text-[16px] shrink-0">radio_button_unchecked</span>
                    <span>Post-quantum lattice inspection</span>
                  </li>
                  <li className="flex items-start gap-1.5">
                    <span className="material-symbols-outlined text-[#869397] text-[16px] shrink-0">radio_button_unchecked</span>
                    <span>Biometric neural handshakes</span>
                  </li>
                  <li className="flex items-start gap-1.5">
                    <span className="material-symbols-outlined text-[#869397] text-[16px] shrink-0">radio_button_unchecked</span>
                    <span>Decentralized threat consensus</span>
                  </li>
                </ul>

                <div className="mt-4 pt-2.5 border-t border-[#3d494c]/20 flex items-center justify-between font-mono text-[11px] text-[#869397]">
                  <span>Target: Nov 2026</span>
                  <span>R&D Roadmap</span>
                </div>
              </div>

            </div>
          </section>

        </div>
      </main>

      {/* FOOTER */}
      <footer className="w-full bg-[#0a0e18] py-8 border-t border-[#3d494c]/30 shadow-[0_-1px_8px_rgba(0,0,0,0.3)] mt-auto z-20">
        <div className="w-full max-w-7xl mx-auto px-4 md:px-8 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex flex-col sm:flex-row items-center gap-4 text-center sm:text-left">
            <span className="font-mono text-xs text-[#bcc9cd]">
              © 2026 CyberShield AI. Neural Threat Defense Protocol.
            </span>
            <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#171b26] border border-[#3d494c]/20">
              <span className="h-1.5 w-1.5 rounded-full bg-[#4edea3]" />
              <span className="font-mono text-[10px] text-[#bcc9cd] uppercase tracking-wider font-semibold">
                SOC2 COMPLIANT // ENCRYPTED
              </span>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-6 font-mono text-xs">
            <button
              type="button"
              onClick={() => setShowInfoModal('status')}
              className="text-[#bcc9cd] hover:text-[#4cd7f6] transition-colors cursor-pointer"
            >
              Security Status
            </button>
            <button
              type="button"
              onClick={() => setShowInfoModal('docs')}
              className="text-[#bcc9cd] hover:text-[#4cd7f6] transition-colors cursor-pointer"
            >
              Documentation
            </button>
            <button
              type="button"
              onClick={() => setShowInfoModal('telemetry')}
              className="text-[#bcc9cd] hover:text-[#4cd7f6] transition-colors cursor-pointer"
            >
              Telemetry API
            </button>
            <button
              type="button"
              onClick={() => setShowInfoModal('privacy')}
              className="text-[#bcc9cd] hover:text-[#4cd7f6] transition-colors cursor-pointer"
            >
              Privacy Policy
            </button>
          </div>
        </div>
      </footer>

      {/* MODAL: INTEL ADVISORY INSPECTOR */}
      {showAdvisoryModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-md p-4 animate-fadeIn">
          <div className="w-full max-w-2xl bg-[#171b26] border border-[#3d494c] rounded-xl p-6 shadow-2xl relative">
            <div className="flex items-center justify-between pb-4 border-b border-[#3d494c]/40">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#ff7f8b] animate-ping" />
                <h3 className="font-mono text-sm font-bold text-[#dfe2f1] uppercase">
                  Global Threat Intel Advisory Hub
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowAdvisoryModal(false)}
                className="text-[#bcc9cd] hover:text-white p-1 rounded hover:bg-[#262a35] cursor-pointer"
              >
                <span className="material-symbols-outlined text-[20px]">close</span>
              </button>
            </div>

            <div className="my-4 max-h-[60vh] overflow-y-auto space-y-3 pr-1">
              {SAMPLE_ADVISORIES.map((advisory) => (
                <div
                  key={advisory.id}
                  className="p-3.5 rounded-lg bg-[#0a0e18] border border-[#3d494c]/30 hover:border-[#4cd7f6]/50 transition-all flex flex-col gap-2"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-[#4cd7f6]">{advisory.cve}</span>
                      <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
                        advisory.severity === 'CRITICAL' ? 'bg-[#ff7f8b]/20 text-[#ffb4ab]' : 'bg-[#4cd7f6]/20 text-[#4cd7f6]'
                      }`}>
                        {advisory.severity} {advisory.score}
                      </span>
                    </div>
                    <span className="font-mono text-[10px] text-[#869397]">{advisory.timeAgo}</span>
                  </div>
                  <h4 className="font-semibold text-sm text-[#dfe2f1]">{advisory.title}</h4>
                  <p className="text-xs text-[#bcc9cd]">{advisory.summary}</p>
                  <div className="mt-1 p-2 rounded bg-[#1c1f2a] border border-[#3d494c]/20 font-mono text-[11px] text-[#4edea3]">
                    <strong>Remediation:</strong> {advisory.remediation}
                  </div>
                </div>
              ))}
            </div>

            <div className="flex justify-end pt-3 border-t border-[#3d494c]/40">
              <button
                type="button"
                onClick={() => setShowAdvisoryModal(false)}
                className="px-4 py-2 rounded-lg bg-[#262a35] hover:bg-[#313540] text-xs font-mono font-semibold text-[#dfe2f1] cursor-pointer"
              >
                Close Feed
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: INFO / DOCS / STATUS MODAL */}
      {showInfoModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-md p-4">
          <div className="w-full max-w-lg bg-[#171b26] border border-[#3d494c] rounded-xl p-6 shadow-2xl relative">
            <div className="flex items-center justify-between pb-3 border-b border-[#3d494c]/40">
              <h3 className="font-mono text-sm font-bold text-[#4cd7f6] uppercase">
                {showInfoModal === 'status' && 'Operational System Health'}
                {showInfoModal === 'docs' && 'CyberShield AI Documentation'}
                {showInfoModal === 'telemetry' && 'Telemetry API Reference'}
                {showInfoModal === 'privacy' && 'Cryptographic Privacy Guarantee'}
                {showInfoModal === 'user' && 'SOC Analyst Session Profile'}
              </h3>
              <button
                type="button"
                onClick={() => setShowInfoModal(null)}
                className="text-[#bcc9cd] hover:text-white p-1 rounded hover:bg-[#262a35] cursor-pointer"
              >
                <span className="material-symbols-outlined text-[20px]">close</span>
              </button>
            </div>

            <div className="my-4 font-mono text-xs text-[#bcc9cd] space-y-2.5">
              {showInfoModal === 'status' && (
                <>
                  <p>All 140+ Neural Security clusters operational with 100% SLA uptime.</p>
                  <div className="p-3 bg-[#0a0e18] rounded border border-[#4edea3]/30 text-[#4edea3]">
                    ✓ Edge Consensus: OPERATIONAL (14ms)<br />
                    ✓ Sandbox Isolation Chamber: ONLINE<br />
                    ✓ Threat Signature Database: SYNCHRONIZED (v2026.4.19)
                  </div>
                </>
              )}
              {showInfoModal === 'docs' && (
                <>
                  <p>CyberShield AI combines transformer-based lexical deobfuscation with behavioral micro-sandboxing.</p>
                  <p>Input strings undergo deep heuristic tokenization, certificate verification, and real-time DNS graph correlation.</p>
                </>
              )}
              {showInfoModal === 'telemetry' && (
                <>
                  <p>Execute programmatic scans using our gRPC / REST endpoint:</p>
                  <pre className="p-2.5 bg-[#0a0e18] rounded text-[#4cd7f6] overflow-x-auto text-[11px]">
                    POST /v1/neural/scan
                    Authorization: Bearer CS_LIVE_KEY_998
                    Content-Type: application/json

                    &#123; "target": "https://suspicious-domain.xyz", "mode": "deep_heuristic" &#125;
                  </pre>
                </>
              )}
              {showInfoModal === 'privacy' && (
                <p>All scanned payloads are ephemeral and analyzed within isolated enclave chambers. No user telemetry is permanently indexed without explicit tenant policy approval.</p>
              )}
              {showInfoModal === 'user' && (
                <div className="p-3 bg-[#0a0e18] rounded border border-[#3d494c]/40 space-y-1">
                  <div><strong>Operator:</strong> Lead SOC Security Engineer</div>
                  <div><strong>Clearance:</strong> Level 4 // Autonomous Quarantine Enabled</div>
                  <div><strong>Enclave ID:</strong> #NODE-TOKYO-08</div>
                  <div><strong>Session Status:</strong> Active (Encrypted TLS 1.3)</div>
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => setShowInfoModal(null)}
                className="px-4 py-1.5 rounded-lg bg-[#06b6d4] text-[#00424f] font-mono text-xs font-bold cursor-pointer hover:bg-[#4cd7f6]"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
