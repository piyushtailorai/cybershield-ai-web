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

export type SimulatedAttackType = 'ddos' | 'phishing' | 'ransomware';

export interface SimulatorLogEntry {
  id: string;
  time: string;
  type: 'CRITICAL' | 'MITIGATION' | 'TELEMETRY' | 'INFO';
  vector: string;
  badge: string;
  message: string;
}

const INITIAL_SIMULATOR_LOGS: SimulatorLogEntry[] = [
  {
    id: 'LOG-INIT-1',
    time: '20:01:14',
    type: 'INFO',
    vector: 'NEURAL-CORE',
    badge: 'HEALTHCHECK',
    message: 'Heuristic deep neural matrix synchronized across 140 operational edge clusters.'
  },
  {
    id: 'LOG-INIT-2',
    time: '20:02:40',
    type: 'TELEMETRY',
    vector: 'INGRESS-SCRUBBER',
    badge: 'NORMAL LOAD',
    message: 'Background ingress telemetry baseline: 142 MB/s, zero payload deviations.'
  },
  {
    id: 'LOG-INIT-3',
    time: '20:04:18',
    type: 'MITIGATION',
    vector: 'HONEYNET-MESH',
    badge: 'INTERCEPT',
    message: 'Deception honeynet probed by autonomous scanner (198.51.100.44). Signature indexed.'
  }
];

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

  // Dynamic advisories for Card 3 feed and modal
  const [advisories, setAdvisories] = useState<AdvisoryItem[]>(SAMPLE_ADVISORIES);

  // Attack simulator states
  const [activeSimulation, setActiveSimulation] = useState<SimulatedAttackType | null>(null);
  const [simulationStatus, setSimulationStatus] = useState<'IDLE' | 'ATTACK_ACTIVE' | 'MITIGATING' | 'NEUTRALIZED'>('IDLE');
  const [pulseAnimationActive, setPulseAnimationActive] = useState<boolean>(false);
  const [threatsNeutralizedCount, setThreatsNeutralizedCount] = useState<number>(4218940);
  const [lossesPreventedCount, setLossesPreventedCount] = useState<number>(18.4);
  const [simulatorLogs, setSimulatorLogs] = useState<SimulatorLogEntry[]>(INITIAL_SIMULATOR_LOGS);
  const [logFilter, setLogFilter] = useState<'ALL' | 'CRITICAL' | 'MITIGATION'>('ALL');
  const [simulatedMetrics, setSimulatedMetrics] = useState({
    ingressRate: '142 MB/s',
    packetRate: '18.4K PPS',
    bandwidthSurge: '0.0%',
    quarantinedNodes: 0,
    defenseEngineStatus: 'STANDBY // MONITORING'
  });

  // Periodic latency simulation for tactical SOC feel (pauses during active attack pulse)
  useEffect(() => {
    if (pulseAnimationActive) return;
    const interval = setInterval(() => {
      setLiveLatency(Math.floor(12 + Math.random() * 5));
    }, 4000);
    return () => clearInterval(interval);
  }, [pulseAnimationActive]);

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

  // Attack simulator dynamic trigger
  const triggerSimulation = (type: SimulatedAttackType) => {
    // 1. Play brief UI pulse animation matching the Tailwind theme
    setPulseAnimationActive(true);
    setActiveSimulation(type);
    setSimulationStatus('ATTACK_ACTIVE');

    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');

    if (type === 'ddos') {
      // 2. Raise Threat Level Gauge
      setCurrentThreat({
        id: `#CX-DDOS-${Math.floor(1000 + Math.random() * 9000)}`,
        target: 'gateway-ingress-cluster.cloud-edge.io',
        score: 94,
        riskLevel: 'CRITICAL',
        signatures: 48,
        anomalies: 9,
        reputation: '4.8%',
        scanTime: 'Just now',
        category: 'Layer-7 Volumetric SYN/UDP Flood Attack'
      });

      // 3. Dynamically trigger live telemetry updates
      setLiveLatency(94);
      setThreatsNeutralizedCount(prev => prev + 18450);
      setLossesPreventedCount(prev => +(prev + 0.6).toFixed(2));
      setSimulatedMetrics({
        ingressRate: '4.82 Tbps',
        packetRate: '38.6M PPS',
        bandwidthSurge: '+1,420% CRITICAL SURGE',
        quarantinedNodes: 1420,
        defenseEngineStatus: 'BGP FLOWSPEC NULL-ROUTE ENGAGED'
      });

      // 4. Append alert entry to real-time activity log (Card 3 feed + modal)
      const newAdvisory: AdvisoryItem = {
        id: `ADV-DDOS-${Date.now()}`,
        cve: 'CVE-2026-9041',
        title: 'Distributed Layer-7 SYN/UDP Volumetric Spike (4.82 Tbps)',
        severity: 'CRITICAL',
        score: '9.6',
        timeAgo: 'Just now',
        summary: 'Massive botnet reflection storm saturating edge ingress proxies with 38.6M PPS.',
        remediation: 'Autonomous BGP FlowSpec null-routing engaged. Neural scrubbing filter applied to edge cluster.'
      };
      setAdvisories(prev => [newAdvisory, ...prev]);

      // 5. Append detailed real-time event logs to simulator activity log
      const newLogs: SimulatorLogEntry[] = [
        {
          id: `LOG-${Date.now()}-1`,
          time: timeStr,
          type: 'CRITICAL',
          vector: 'DDoS-DETECTION',
          badge: '4.82 Tbps SPIKE',
          message: 'CRITICAL: Volumetric SYN-flood spike detected on port 443 across 1,420 ingress reflection proxies.'
        },
        {
          id: `LOG-${Date.now()}-2`,
          time: timeStr,
          type: 'TELEMETRY',
          vector: 'BANDWIDTH-SURGE',
          badge: '+1,420% INGRESS',
          message: 'Telemetry surge: Packet arrival rate elevated to 38.6M PPS. Threat level gauge raised to 94/100.'
        },
        {
          id: `LOG-${Date.now()}-3`,
          time: timeStr,
          type: 'MITIGATION',
          vector: 'BGP-FLOWSPEC',
          badge: 'AUTONOMOUS DEFENSE',
          message: 'Mitigation executed: Neural scrubber sinkholed 14,200 botnet IPs. Zero service disruption.'
        }
      ];
      setSimulatorLogs(prev => [...newLogs, ...prev]);

    } else if (type === 'phishing') {
      // 2. Raise Threat Level Gauge
      setCurrentThreat({
        id: `#CX-PHISH-${Math.floor(1000 + Math.random() * 9000)}`,
        target: 'auth.corp-sso-verify-portal.net/login',
        score: 91,
        riskLevel: 'CRITICAL',
        signatures: 34,
        anomalies: 7,
        reputation: '11.4%',
        scanTime: 'Just now',
        category: 'AI Voice-Clone & OAuth Session Token Harvester'
      });

      // 3. Dynamically trigger live telemetry updates
      setLiveLatency(52);
      setThreatsNeutralizedCount(prev => prev + 3420);
      setLossesPreventedCount(prev => +(prev + 1.2).toFixed(2));
      setSimulatedMetrics({
        ingressRate: '1.4 GB/s',
        packetRate: '890 Auth Req/s',
        bandwidthSurge: '+680% Infiltration Surge',
        quarantinedNodes: 340,
        defenseEngineStatus: 'FIDO3 BIOMETRIC STEP-UP ENFORCED'
      });

      // 4. Append alert entry to real-time activity log (Card 3 feed + modal)
      const newAdvisory: AdvisoryItem = {
        id: `ADV-PHISH-${Date.now()}`,
        cve: 'CVE-2026-9102',
        title: 'Mass AI-Voice Clone & OAuth Token Phishing Campaign',
        severity: 'CRITICAL',
        score: '9.2',
        timeAgo: 'Just now',
        summary: 'Synchronized credential harvest barrage targeting 340 corporate SSO/SAML authorization endpoints.',
        remediation: 'All compromised bearer tokens revoked. Step-up FIDO3 cryptographic challenge enforced.'
      };
      setAdvisories(prev => [newAdvisory, ...prev]);

      // 5. Append detailed real-time event logs to simulator activity log
      const newLogs: SimulatorLogEntry[] = [
        {
          id: `LOG-${Date.now()}-1`,
          time: timeStr,
          type: 'CRITICAL',
          vector: 'PHISH-OUTBREAK',
          badge: 'SSO INTERCEPT',
          message: 'CRITICAL: Synthetic AI neural voice authentication requests targeted 340 corporate executive accounts.'
        },
        {
          id: `LOG-${Date.now()}-2`,
          time: timeStr,
          type: 'TELEMETRY',
          vector: 'AUTH-SPIKE',
          badge: '+680% TOKEN CALLS',
          message: 'Telemetry update: OAuth refresh velocity spike detected. Threat score raised to 91/100 CRITICAL.'
        },
        {
          id: `LOG-${Date.now()}-3`,
          time: timeStr,
          type: 'MITIGATION',
          vector: 'FIDO3-CHALLENGE',
          badge: 'CREDENTIALS SAVED',
          message: 'Mitigation executed: 340 compromised sessions revoked. Hardware FIDO3 isolation challenge enforced.'
        }
      ];
      setSimulatorLogs(prev => [...newLogs, ...prev]);

    } else if (type === 'ransomware') {
      // 2. Raise Threat Level Gauge (Max elevation)
      setCurrentThreat({
        id: `#CX-RANSOM-${Math.floor(1000 + Math.random() * 9000)}`,
        target: 'vssadmin.exe-enclave-sandbox-fork#99',
        score: 99,
        riskLevel: 'CRITICAL',
        signatures: 62,
        anomalies: 16,
        reputation: '0.9%',
        scanTime: 'Just now',
        category: 'Zero-Day Polymorphic Volume Shadow Encryption Payload'
      });

      // 3. Dynamically trigger live telemetry updates
      setLiveLatency(118);
      setThreatsNeutralizedCount(prev => prev + 890);
      setLossesPreventedCount(prev => +(prev + 3.8).toFixed(2));
      setSimulatedMetrics({
        ingressRate: '3.6 GB/s Memory I/O',
        packetRate: '7.8K Syscalls/s',
        bandwidthSurge: '+960% Lateral Probe Surge',
        quarantinedNodes: 48,
        defenseEngineStatus: 'MICRO-ENCLAVE SIGKILL EXECUTION'
      });

      // 4. Append alert entry to real-time activity log (Card 3 feed + modal)
      const newAdvisory: AdvisoryItem = {
        id: `ADV-RANSOM-${Date.now()}`,
        cve: 'CVE-2026-9988',
        title: 'Polymorphic Enclave Shadow-Copy Encryption Payload',
        severity: 'CRITICAL',
        score: '9.9',
        timeAgo: 'Just now',
        summary: 'Lateral memory injection and Volume Shadow Copy wipe attempt executed via weaponized vssadmin child process.',
        remediation: 'Micro-enclave memory sandbox isolated 48,200 files. Zero bytes encrypted. Payload terminated.'
      };
      setAdvisories(prev => [newAdvisory, ...prev]);

      // 5. Append detailed real-time event logs to simulator activity log
      const newLogs: SimulatorLogEntry[] = [
        {
          id: `LOG-${Date.now()}-1`,
          time: timeStr,
          type: 'CRITICAL',
          vector: 'RANSOMWARE-INJECTION',
          badge: 'ENCLAVE BREACH ATTEMPT',
          message: 'CRITICAL: Polymorphic encryptor attempted Volume Shadow Copy deletion via hooked vssadmin.exe process.'
        },
        {
          id: `LOG-${Date.now()}-2`,
          time: timeStr,
          type: 'TELEMETRY',
          vector: 'IO-SYS-SPIKE',
          badge: '+960% MEMORY I/O',
          message: 'Telemetry update: Unauthorized cryptographic API handles trapped. Threat gauge raised to MAXIMUM 99/100.'
        },
        {
          id: `LOG-${Date.now()}-3`,
          time: timeStr,
          type: 'MITIGATION',
          vector: 'ENCLAVE-SIGKILL',
          badge: 'ZERO DATA LOSS',
          message: 'Mitigation executed: Process SIGKILL dispatched in 14ms. All 48,200 enterprise files preserved.'
        }
      ];
      setSimulatorLogs(prev => [...newLogs, ...prev]);
    }

    // Sequence stages of autonomous AI defense
    setTimeout(() => {
      setSimulationStatus('MITIGATING');
    }, 1800);

    setTimeout(() => {
      setSimulationStatus('NEUTRALIZED');
      setPulseAnimationActive(false);
      setLiveLatency(Math.floor(14 + Math.random() * 4));
    }, 3600);
  };

  const handleResetBaseline = () => {
    setPulseAnimationActive(false);
    setActiveSimulation(null);
    setSimulationStatus('IDLE');
    setLiveLatency(14);
    setCurrentThreat({
      id: '#CX-BASE-001',
      target: 'corporate-network-mesh.clean',
      score: 4,
      riskLevel: 'CLEAN',
      signatures: 0,
      anomalies: 0,
      reputation: '99.9%',
      scanTime: 'Just now',
      category: 'All Threat Vectors Absent // Verified Baseline'
    });
    setSimulatedMetrics({
      ingressRate: '142 MB/s',
      packetRate: '18.4K PPS',
      bandwidthSurge: '0.0%',
      quarantinedNodes: 0,
      defenseEngineStatus: 'STANDBY // MONITORING'
    });
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
    setSimulatorLogs(prev => [
      {
        id: `LOG-${Date.now()}`,
        time: timeStr,
        type: 'INFO',
        vector: 'BASELINE-RESTORE',
        badge: 'NORMALIZED',
        message: 'SOC baseline restored. All threat vectors normalized to clean state (4/100).'
      },
      ...prev
    ]);
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
                href="#threat-simulator"
                className={`px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 ${
                  activeSimulation
                    ? 'bg-[#ff7f8b]/20 text-[#ffb4ab] border border-[#ff7f8b]/40 font-bold animate-pulse'
                    : 'text-[#bcc9cd] hover:bg-[#1c1f2a] hover:text-[#ffb4ab]'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${activeSimulation ? 'bg-[#ff7f8b] animate-ping' : 'bg-[#4cd7f6]'}`} />
                Attack Simulator
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
              className={`flex flex-col bg-[#171b26]/90 backdrop-blur-xl p-5 md:p-6 rounded-xl border transition-all duration-500 justify-between relative overflow-hidden group ${
                pulseAnimationActive
                  ? 'border-[#ff7f8b] ring-2 ring-[#ff7f8b]/70 shadow-[0_0_35px_rgba(255,127,139,0.35)] animate-pulse'
                  : 'border-[#3d494c]/30 shadow-[0_15px_35px_rgba(0,0,0,0.5)]'
              }`}
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
                        stroke={currentThreat.score >= 80 ? '#ff7f8b' : currentThreat.score > 30 ? '#06b6d4' : '#4edea3'}
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

                  <div className={`mt-2 px-3 py-1 rounded-full font-mono text-[11px] font-semibold tracking-wider transition-colors duration-500 ${
                    currentThreat.riskLevel === 'CLEAN'
                      ? 'bg-[#4edea3]/20 text-[#4edea3]'
                      : currentThreat.riskLevel === 'CRITICAL'
                      ? 'bg-[#ff7f8b]/20 text-[#ff7f8b]'
                      : 'bg-[#ff7f8b]/20 text-[#ffb4ab]'
                  }`}>
                    {currentThreat.riskLevel === 'CLEAN'
                      ? 'ALL THREATS ABSENT // VERIFIED'
                      : currentThreat.riskLevel === 'CRITICAL'
                      ? 'CRITICAL VECTOR DETECTED // MITIGATING'
                      : 'HIGH RISK MITIGATED'}
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
                  <div className="bg-[#1c1f2a] p-3 rounded-lg flex flex-col justify-center border border-[#3d494c]/20 transition-all">
                    <span className="text-2xl font-bold text-[#4cd7f6] leading-tight font-mono">
                      {(threatsNeutralizedCount / 1000000).toFixed(2)}M+
                    </span>
                    <span className="font-mono text-[11px] text-[#bcc9cd] mt-0.5">Threats Neutralized</span>
                  </div>

                  <div className="bg-[#1c1f2a] p-3 rounded-lg flex flex-col justify-center border border-[#3d494c]/20">
                    <span className="text-2xl font-bold text-[#4edea3] leading-tight font-mono">99.98%</span>
                    <span className="font-mono text-[11px] text-[#bcc9cd] mt-0.5">True-Positive Accuracy</span>
                  </div>

                  <div className="bg-[#1c1f2a] p-3 rounded-lg flex flex-col justify-center border border-[#3d494c]/20">
                    <span className={`text-2xl font-bold leading-tight font-mono transition-colors duration-300 ${
                      liveLatency > 60 ? 'text-[#ff7f8b]' : 'text-[#dfe2f1]'
                    }`}>
                      {liveLatency}ms
                    </span>
                    <span className="font-mono text-[11px] text-[#bcc9cd] mt-0.5">Live Neural Latency</span>
                  </div>

                  <div className="bg-[#1c1f2a] p-3 rounded-lg flex flex-col justify-center border border-[#3d494c]/20">
                    <span className="text-2xl font-bold text-[#4edea3] leading-tight font-mono">
                      ${lossesPreventedCount.toFixed(1)}M
                    </span>
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
                  {advisories.slice(0, 3).map((advisory) => (
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
                  <span>Explore All {advisories.length + 38} Active Intel Advisories</span>
                  <span className="material-symbols-outlined text-[16px] group-hover:translate-x-1 transition-transform">
                    arrow_forward
                  </span>
                </button>
              </div>
            </div>

          </section>

          {/* ========================================================================= */}
          {/* 2.5 LIVE THREAT ATTACK SIMULATOR MODULE */}
          {/* Placed directly below the primary metrics overview */}
          {/* ========================================================================= */}
          <section
            id="threat-simulator"
            className={`flex flex-col w-full bg-[#171b26]/85 backdrop-blur-xl p-5 md:p-8 rounded-xl border transition-all duration-700 relative overflow-hidden ${
              pulseAnimationActive
                ? 'border-[#ff7f8b] ring-2 ring-[#ff7f8b]/60 shadow-[0_0_50px_rgba(255,127,139,0.35)] animate-pulse'
                : 'border-[#3d494c]/30 shadow-[0_15px_40px_rgba(0,0,0,0.6)]'
            }`}
          >
            {/* Ambient Lighting Gradients */}
            <div className="absolute -top-20 -left-20 w-72 h-72 rounded-full bg-[#ff7f8b]/10 blur-[70px] pointer-events-none" />
            <div className="absolute -bottom-20 -right-20 w-80 h-80 rounded-full bg-[#06b6d4]/10 blur-[80px] pointer-events-none" />

            {/* Header with Status Beacon & Baseline Reset */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-[#3d494c]/20 relative z-10">
              <div>
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2.5 w-2.5">
                    <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                      pulseAnimationActive ? 'bg-[#ff7f8b]' : 'bg-[#4cd7f6]'
                    }`} />
                    <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                      pulseAnimationActive ? 'bg-[#ff7f8b]' : 'bg-[#4cd7f6]'
                    }`} />
                  </span>
                  <span className="font-mono text-[10px] text-[#4cd7f6] uppercase tracking-widest font-bold">
                    TACTICAL THREAT ENGINE // HEURISTIC STRESS-TEST
                  </span>
                  {activeSimulation && (
                    <span className="ml-1 px-2 py-0.5 rounded-full font-mono text-[10px] font-bold bg-[#ff7f8b]/20 text-[#ffb4ab] border border-[#ff7f8b]/30 animate-pulse">
                      ACTIVE ADVERSARY SIMULATION
                    </span>
                  )}
                </div>
                <h2 className="text-2xl md:text-3xl text-[#dfe2f1] font-extrabold mt-1 tracking-tight flex items-center gap-3">
                  <span>Live Threat Attack Simulator</span>
                </h2>
                <p className="text-xs md:text-sm text-[#bcc9cd] max-w-2xl mt-1">
                  Inject live weaponized adversary vectors directly into the CyberShield neural telemetry pipeline to evaluate automated containment, telemetry surges, and SIEM alerting.
                </p>
              </div>

              {/* Status Controls */}
              <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                <div className={`px-3 py-1.5 rounded-lg font-mono text-xs font-semibold flex items-center gap-2 border ${
                  simulationStatus === 'ATTACK_ACTIVE'
                    ? 'bg-[#ff7f8b]/20 text-[#ffb4ab] border-[#ff7f8b]/40 animate-pulse'
                    : simulationStatus === 'MITIGATING'
                    ? 'bg-[#f59e0b]/20 text-[#fcd34d] border-[#f59e0b]/40 animate-pulse'
                    : simulationStatus === 'NEUTRALIZED'
                    ? 'bg-[#4edea3]/20 text-[#4edea3] border-[#4edea3]/40'
                    : 'bg-[#1c1f2a] text-[#bcc9cd] border-[#3d494c]/30'
                }`}>
                  <span className={`w-2 h-2 rounded-full ${
                    simulationStatus === 'ATTACK_ACTIVE'
                      ? 'bg-[#ff7f8b] animate-ping'
                      : simulationStatus === 'MITIGATING'
                      ? 'bg-[#f59e0b] animate-spin'
                      : simulationStatus === 'NEUTRALIZED'
                      ? 'bg-[#4edea3]'
                      : 'bg-[#869397]'
                  }`} />
                  <span>
                    {simulationStatus === 'ATTACK_ACTIVE' && 'VECTOR INJECTED // UNDER ATTACK'}
                    {simulationStatus === 'MITIGATING' && 'AUTONOMOUS AI MITIGATION ENGAGED'}
                    {simulationStatus === 'NEUTRALIZED' && 'THREAT CONFINED // ZERO DATA LOSS'}
                    {simulationStatus === 'IDLE' && 'DEFENSE ENGINE READY // STANDBY'}
                  </span>
                </div>

                <button
                  type="button"
                  onClick={handleResetBaseline}
                  className="px-3 py-1.5 rounded-lg bg-[#1c1f2a] hover:bg-[#262a35] text-[#bcc9cd] hover:text-[#4edea3] border border-[#3d494c]/30 hover:border-[#4edea3]/40 font-mono text-xs font-semibold transition-all flex items-center gap-1.5 cursor-pointer"
                  title="Normalize threat gauge and restore clean baseline"
                >
                  <span className="material-symbols-outlined text-[16px]">restart_alt</span>
                  <span>Reset Baseline</span>
                </button>
              </div>
            </div>

            {/* Tactical Alert Notification Banner (When attack is pulsing / active) */}
            {activeSimulation && (
              <div className={`my-4 p-3.5 rounded-lg border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 transition-all duration-500 relative z-10 ${
                pulseAnimationActive
                  ? 'bg-[#ff7f8b]/15 border-[#ff7f8b]/40 text-[#ffb4ab] shadow-[0_0_25px_rgba(255,127,139,0.2)] animate-pulse'
                  : 'bg-[#4edea3]/10 border-[#4edea3]/30 text-[#4edea3]'
              }`}>
                <div className="flex items-center gap-3">
                  <span className={`material-symbols-outlined text-[24px] shrink-0 ${
                    pulseAnimationActive ? 'text-[#ff7f8b] animate-bounce' : 'text-[#4edea3]'
                  }`}>
                    {pulseAnimationActive ? 'warning' : 'verified_user'}
                  </span>
                  <div>
                    <div className="font-mono text-xs font-bold flex items-center gap-2">
                      <span>
                        {activeSimulation === 'ddos' && '[IN PROGRESS] Layer-7 SYN/UDP Volumetric Saturation'}
                        {activeSimulation === 'phishing' && '[IN PROGRESS] AI-Voice Clone & SAML Credential Exfiltration'}
                        {activeSimulation === 'ransomware' && '[IN PROGRESS] Polymorphic Shadow-Volume Encryption Detonation'}
                      </span>
                      <span className="text-[10px] uppercase px-1.5 py-0.2 rounded bg-black/40">
                        {simulationStatus}
                      </span>
                    </div>
                    <p className="text-[11px] opacity-90 mt-0.5 font-sans">
                      {pulseAnimationActive
                        ? 'Threat assessment gauge elevated to critical. Ingress scrubbers dynamically filtering packet traffic across corporate nodes.'
                        : 'Autonomous neural mitigations successful. Vector isolated within sandbox chamber; threat records indexed.'}
                    </p>
                  </div>
                </div>

                <div className="font-mono text-[11px] shrink-0 self-end sm:self-auto bg-black/40 px-3 py-1 rounded border border-white/10 flex items-center gap-2">
                  <span className="text-[#869397]">LATENCY:</span>
                  <span className={liveLatency > 60 ? 'text-[#ff7f8b] font-bold' : 'text-[#4edea3] font-bold'}>
                    {liveLatency}ms
                  </span>
                  <span className="text-[#869397]">| THREAT:</span>
                  <span className="text-[#ff7f8b] font-bold">{currentThreat.score}/100</span>
                </div>
              </div>
            )}

            {/* The 3 Simulation Action Cards/Buttons */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 my-6 relative z-10">

              {/* BUTTON 1: DDoS SPIKE */}
              <div
                className={`flex flex-col justify-between p-4 md:p-5 rounded-xl border transition-all duration-300 relative overflow-hidden group ${
                  activeSimulation === 'ddos' && pulseAnimationActive
                    ? 'bg-[#1c1f2a] border-[#ff7f8b] ring-2 ring-[#ff7f8b]/70 shadow-[0_0_30px_rgba(255,127,139,0.35)] animate-attack-pulse'
                    : 'bg-[#1c1f2a]/80 hover:bg-[#1c1f2a] border-[#3d494c]/30 hover:border-[#4cd7f6]/50 shadow-lg'
                }`}
              >
                <div className="flex items-center justify-between pb-3">
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 rounded-lg bg-[#06b6d4]/20 border border-[#06b6d4]/30 flex items-center justify-center text-[#4cd7f6]">
                      <span className="material-symbols-outlined text-[18px]">waves</span>
                    </div>
                    <div>
                      <span className="font-mono text-[10px] text-[#4cd7f6] uppercase tracking-wider font-bold">
                        VECTOR 01 // L7 FLOOD
                      </span>
                      <div className="text-[11px] font-mono text-[#869397]">SYN / UDP Ingress</div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-[#ff7f8b]/20 text-[#ffb4ab]">
                    SCORE: 94
                  </span>
                </div>

                <div className="my-2">
                  <h3 className="text-base font-bold text-[#dfe2f1] group-hover:text-[#4cd7f6] transition-colors">
                    Volumetric DDoS Spike
                  </h3>
                  <p className="text-xs text-[#bcc9cd] mt-1 line-clamp-2">
                    Saturates corporate ingress gateways with 4.82 Tbps distributed reflection traffic across 14,200 botnet endpoints.
                  </p>

                  <div className="grid grid-cols-2 gap-2 mt-3 pt-2 border-t border-[#3d494c]/20 font-mono text-[11px]">
                    <div className="bg-[#0a0e18] p-1.5 rounded">
                      <div className="text-[#869397] text-[10px]">PEAK BANDWIDTH</div>
                      <div className="text-[#ffb4ab] font-bold">4.82 Tbps</div>
                    </div>
                    <div className="bg-[#0a0e18] p-1.5 rounded">
                      <div className="text-[#869397] text-[10px]">PACKET SURGE</div>
                      <div className="text-[#4cd7f6] font-bold">38.6M PPS</div>
                    </div>
                  </div>
                </div>

                <div className="pt-3 mt-2 border-t border-[#3d494c]/20">
                  <button
                    type="button"
                    onClick={() => triggerSimulation('ddos')}
                    className={`w-full py-2.5 px-4 rounded-lg font-mono text-xs font-bold flex items-center justify-center gap-2 transition-all cursor-pointer shadow-md ${
                      activeSimulation === 'ddos' && pulseAnimationActive
                        ? 'bg-[#ff7f8b] text-[#3e0007] shadow-[0_0_20px_#ff7f8b] ring-2 ring-white/50'
                        : 'bg-[#262a35] hover:bg-[#06b6d4] text-[#dfe2f1] hover:text-[#00424f] hover:shadow-[0_0_18px_rgba(6,182,212,0.5)]'
                    }`}
                  >
                    <span className="material-symbols-outlined text-[16px]">
                      {activeSimulation === 'ddos' && pulseAnimationActive ? 'emergency' : 'play_arrow'}
                    </span>
                    <span>Simulate DDoS Spike</span>
                  </button>
                </div>
              </div>

              {/* BUTTON 2: PHISHING OUTBREAK */}
              <div
                className={`flex flex-col justify-between p-4 md:p-5 rounded-xl border transition-all duration-300 relative overflow-hidden group ${
                  activeSimulation === 'phishing' && pulseAnimationActive
                    ? 'bg-[#1c1f2a] border-[#ff7f8b] ring-2 ring-[#ff7f8b]/70 shadow-[0_0_30px_rgba(255,127,139,0.35)] animate-attack-pulse'
                    : 'bg-[#1c1f2a]/80 hover:bg-[#1c1f2a] border-[#3d494c]/30 hover:border-[#f59e0b]/50 shadow-lg'
                }`}
              >
                <div className="flex items-center justify-between pb-3">
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 rounded-lg bg-[#f59e0b]/20 border border-[#f59e0b]/30 flex items-center justify-center text-[#fcd34d]">
                      <span className="material-symbols-outlined text-[18px]">mark_email_unread</span>
                    </div>
                    <div>
                      <span className="font-mono text-[10px] text-[#fcd34d] uppercase tracking-wider font-bold">
                        VECTOR 02 // CREDENTIAL THEFT
                      </span>
                      <div className="text-[11px] font-mono text-[#869397]">SSO / Token Hijack</div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-[#ff7f8b]/20 text-[#ffb4ab]">
                    SCORE: 91
                  </span>
                </div>

                <div className="my-2">
                  <h3 className="text-base font-bold text-[#dfe2f1] group-hover:text-[#fcd34d] transition-colors">
                    Simulated Phishing Outbreak
                  </h3>
                  <p className="text-xs text-[#bcc9cd] mt-1 line-clamp-2">
                    Detonates targeted AI neural voice-clone login requests and malicious SAML authorization storms against 340 enterprise mailboxes.
                  </p>

                  <div className="grid grid-cols-2 gap-2 mt-3 pt-2 border-t border-[#3d494c]/20 font-mono text-[11px]">
                    <div className="bg-[#0a0e18] p-1.5 rounded">
                      <div className="text-[#869397] text-[10px]">TARGET MAILBOXES</div>
                      <div className="text-[#fcd34d] font-bold">340 Accounts</div>
                    </div>
                    <div className="bg-[#0a0e18] p-1.5 rounded">
                      <div className="text-[#869397] text-[10px]">TOKEN INTERCEPTION</div>
                      <div className="text-[#4edea3] font-bold">100% Blocked</div>
                    </div>
                  </div>
                </div>

                <div className="pt-3 mt-2 border-t border-[#3d494c]/20">
                  <button
                    type="button"
                    onClick={() => triggerSimulation('phishing')}
                    className={`w-full py-2.5 px-4 rounded-lg font-mono text-xs font-bold flex items-center justify-center gap-2 transition-all cursor-pointer shadow-md ${
                      activeSimulation === 'phishing' && pulseAnimationActive
                        ? 'bg-[#ff7f8b] text-[#3e0007] shadow-[0_0_20px_#ff7f8b] ring-2 ring-white/50'
                        : 'bg-[#262a35] hover:bg-[#f59e0b] text-[#dfe2f1] hover:text-[#3e1e00] hover:shadow-[0_0_18px_rgba(245,158,11,0.5)]'
                    }`}
                  >
                    <span className="material-symbols-outlined text-[16px]">
                      {activeSimulation === 'phishing' && pulseAnimationActive ? 'emergency' : 'play_arrow'}
                    </span>
                    <span>Simulate Phishing Outbreak</span>
                  </button>
                </div>
              </div>

              {/* BUTTON 3: RANSOMWARE INFILTRATION */}
              <div
                className={`flex flex-col justify-between p-4 md:p-5 rounded-xl border transition-all duration-300 relative overflow-hidden group ${
                  activeSimulation === 'ransomware' && pulseAnimationActive
                    ? 'bg-[#1c1f2a] border-[#ff7f8b] ring-2 ring-[#ff7f8b]/70 shadow-[0_0_30px_rgba(255,127,139,0.35)] animate-attack-pulse'
                    : 'bg-[#1c1f2a]/80 hover:bg-[#1c1f2a] border-[#3d494c]/30 hover:border-[#ff7f8b]/50 shadow-lg'
                }`}
              >
                <div className="flex items-center justify-between pb-3">
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 rounded-lg bg-[#ff7f8b]/20 border border-[#ff7f8b]/30 flex items-center justify-center text-[#ff7f8b]">
                      <span className="material-symbols-outlined text-[18px]">lock</span>
                    </div>
                    <div>
                      <span className="font-mono text-[10px] text-[#ff7f8b] uppercase tracking-wider font-bold">
                        VECTOR 03 // ZERO-DAY LOCK
                      </span>
                      <div className="text-[11px] font-mono text-[#869397]">Volume Shadow Wipe</div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-[#ff7f8b]/20 text-[#ffb4ab]">
                    SCORE: 99
                  </span>
                </div>

                <div className="my-2">
                  <h3 className="text-base font-bold text-[#dfe2f1] group-hover:text-[#ff7f8b] transition-colors">
                    Ransomware Infiltration
                  </h3>
                  <p className="text-xs text-[#bcc9cd] mt-1 line-clamp-2">
                    Injects polymorphic memory encryptors attempting to delete Volume Shadow Copies via hooked vssadmin child processes.
                  </p>

                  <div className="grid grid-cols-2 gap-2 mt-3 pt-2 border-t border-[#3d494c]/20 font-mono text-[11px]">
                    <div className="bg-[#0a0e18] p-1.5 rounded">
                      <div className="text-[#869397] text-[10px]">ISOLATED PAYLOAD</div>
                      <div className="text-[#ff7f8b] font-bold">14ms SIGKILL</div>
                    </div>
                    <div className="bg-[#0a0e18] p-1.5 rounded">
                      <div className="text-[#869397] text-[10px]">ENCRYPTED DATA</div>
                      <div className="text-[#4edea3] font-bold">0 Bytes (100% Safe)</div>
                    </div>
                  </div>
                </div>

                <div className="pt-3 mt-2 border-t border-[#3d494c]/20">
                  <button
                    type="button"
                    onClick={() => triggerSimulation('ransomware')}
                    className={`w-full py-2.5 px-4 rounded-lg font-mono text-xs font-bold flex items-center justify-center gap-2 transition-all cursor-pointer shadow-md ${
                      activeSimulation === 'ransomware' && pulseAnimationActive
                        ? 'bg-[#ff7f8b] text-[#3e0007] shadow-[0_0_20px_#ff7f8b] ring-2 ring-white/50'
                        : 'bg-[#262a35] hover:bg-[#ff7f8b] text-[#dfe2f1] hover:text-[#3e0007] hover:shadow-[0_0_18px_rgba(255,127,139,0.5)]'
                    }`}
                  >
                    <span className="material-symbols-outlined text-[16px]">
                      {activeSimulation === 'ransomware' && pulseAnimationActive ? 'emergency' : 'play_arrow'}
                    </span>
                    <span>Simulate Ransomware Infiltration</span>
                  </button>
                </div>
              </div>

            </div>

            {/* Live Telemetry HUD Bar */}
            <div className="p-4 rounded-xl bg-[#0a0e18]/80 border border-[#3d494c]/30 my-2 relative z-10">
              <div className="flex items-center justify-between pb-3 border-b border-[#3d494c]/20">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#06b6d4] shadow-[0_0_6px_#06b6d4]" />
                  <span className="font-mono text-[10px] text-[#4cd7f6] uppercase tracking-wider font-bold">
                    LIVE SIMULATOR TELEMETRY CHANNELS
                  </span>
                </div>
                <span className="font-mono text-[10px] text-[#869397]">
                  STREAM FREQUENCY: 100ms
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-3 font-mono">
                <div className="bg-[#171b26] p-2.5 rounded-lg border border-[#3d494c]/20 flex flex-col">
                  <span className="text-[10px] text-[#869397] uppercase">Ingress Telemetry</span>
                  <span className="text-base md:text-lg font-bold text-[#dfe2f1] mt-0.5 truncate">
                    {simulatedMetrics.ingressRate}
                  </span>
                  <span className="text-[10px] text-[#4cd7f6] mt-0.5">
                    {simulatedMetrics.packetRate}
                  </span>
                </div>

                <div className="bg-[#171b26] p-2.5 rounded-lg border border-[#3d494c]/20 flex flex-col">
                  <span className="text-[10px] text-[#869397] uppercase">Traffic Surge Delta</span>
                  <span className={`text-base md:text-lg font-bold mt-0.5 truncate ${
                    simulatedMetrics.bandwidthSurge.includes('+') ? 'text-[#ff7f8b]' : 'text-[#4edea3]'
                  }`}>
                    {simulatedMetrics.bandwidthSurge}
                  </span>
                  <span className="text-[10px] text-[#869397] mt-0.5">
                    {simulatedMetrics.quarantinedNodes > 0 ? `${simulatedMetrics.quarantinedNodes} Nodes Quarantined` : 'Nominal Threshold'}
                  </span>
                </div>

                <div className="bg-[#171b26] p-2.5 rounded-lg border border-[#3d494c]/20 flex flex-col">
                  <span className="text-[10px] text-[#869397] uppercase">Gauge Score Elevation</span>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className={`text-base md:text-lg font-bold ${
                      currentThreat.score > 80 ? 'text-[#ff7f8b]' : currentThreat.score > 30 ? 'text-[#06b6d4]' : 'text-[#4edea3]'
                    }`}>
                      {currentThreat.score} / 100
                    </span>
                    <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${
                      currentThreat.riskLevel === 'CRITICAL' ? 'bg-[#ff7f8b]/20 text-[#ff7f8b]' : 'bg-[#4edea3]/20 text-[#4edea3]'
                    }`}>
                      {currentThreat.riskLevel}
                    </span>
                  </div>
                  <div className="w-full bg-[#1c1f2a] h-1.5 rounded-full mt-1.5 overflow-hidden">
                    <div
                      className={`h-full transition-all duration-700 ${
                        currentThreat.score > 80 ? 'bg-[#ff7f8b]' : currentThreat.score > 30 ? 'bg-[#06b6d4]' : 'bg-[#4edea3]'
                      }`}
                      style={{ width: `${currentThreat.score}%` }}
                    />
                  </div>
                </div>

                <div className="bg-[#171b26] p-2.5 rounded-lg border border-[#3d494c]/20 flex flex-col">
                  <span className="text-[10px] text-[#869397] uppercase">Autonomous Engine</span>
                  <span className="text-xs md:text-sm font-bold text-[#4edea3] mt-0.5 truncate">
                    {simulatedMetrics.defenseEngineStatus}
                  </span>
                  <span className="text-[10px] text-[#869397] mt-0.5">
                    Latency: {liveLatency}ms | SLA: 100%
                  </span>
                </div>
              </div>
            </div>

            {/* Real-Time Activity Log & Event Stream */}
            <div className="mt-4 pt-4 border-t border-[#3d494c]/20 relative z-10">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#4edea3] opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-[#4edea3]" />
                  </span>
                  <h3 className="font-mono text-xs font-bold text-[#dfe2f1] uppercase tracking-wider">
                    Real-Time Activity Log & Telemetry Console
                  </h3>
                  <span className="px-2 py-0.5 rounded bg-[#1c1f2a] text-[#869397] font-mono text-[10px]">
                    {simulatorLogs.length} Events Logged
                  </span>
                </div>

                {/* Filter and Clear */}
                <div className="flex items-center gap-1.5 font-mono text-[11px]">
                  <button
                    type="button"
                    onClick={() => setLogFilter('ALL')}
                    className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                      logFilter === 'ALL'
                        ? 'bg-[#06b6d4] text-[#00424f] font-bold'
                        : 'bg-[#1c1f2a] text-[#bcc9cd] hover:text-[#dfe2f1]'
                    }`}
                  >
                    All ({simulatorLogs.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setLogFilter('CRITICAL')}
                    className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                      logFilter === 'CRITICAL'
                        ? 'bg-[#ff7f8b] text-[#3e0007] font-bold'
                        : 'bg-[#1c1f2a] text-[#bcc9cd] hover:text-[#ffb4ab]'
                    }`}
                  >
                    Critical ({simulatorLogs.filter(l => l.type === 'CRITICAL').length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setLogFilter('MITIGATION')}
                    className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                      logFilter === 'MITIGATION'
                        ? 'bg-[#4edea3] text-[#00381f] font-bold'
                        : 'bg-[#1c1f2a] text-[#bcc9cd] hover:text-[#4edea3]'
                    }`}
                  >
                    Mitigations ({simulatorLogs.filter(l => l.type === 'MITIGATION').length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setSimulatorLogs([])}
                    className="p-1 rounded text-[#869397] hover:text-[#dfe2f1] hover:bg-[#1c1f2a] cursor-pointer ml-1"
                    title="Clear activity log"
                  >
                    <span className="material-symbols-outlined text-[16px]">delete_sweep</span>
                  </button>
                </div>
              </div>

              {/* Terminal Viewport */}
              <div className="bg-[#0a0e18] border border-[#3d494c]/40 rounded-lg p-3 max-h-56 overflow-y-auto space-y-2 font-mono text-xs shadow-inner">
                {simulatorLogs
                  .filter(l => logFilter === 'ALL' || l.type === logFilter)
                  .map((log) => (
                    <div
                      key={log.id}
                      className="flex flex-col sm:flex-row sm:items-baseline gap-1 sm:gap-2.5 p-2 rounded bg-[#171b26]/50 hover:bg-[#171b26] border border-[#3d494c]/20 transition-all text-[11px]"
                    >
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-[#869397] text-[10px]">[{log.time}]</span>
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold shrink-0 ${
                          log.type === 'CRITICAL'
                            ? 'bg-[#ff7f8b]/20 text-[#ffb4ab] border border-[#ff7f8b]/40'
                            : log.type === 'MITIGATION'
                            ? 'bg-[#4edea3]/20 text-[#4edea3] border border-[#4edea3]/40'
                            : log.type === 'TELEMETRY'
                            ? 'bg-[#06b6d4]/20 text-[#4cd7f6] border border-[#06b6d4]/40'
                            : 'bg-[#262a35] text-[#bcc9cd]'
                        }`}>
                          {log.badge}
                        </span>
                        <span className="text-[#4cd7f6] font-semibold text-[10px]">
                          [{log.vector}]
                        </span>
                      </div>
                      <p className="text-[#dfe2f1] flex-1 leading-snug">
                        {log.message}
                      </p>
                    </div>
                  ))}

                {simulatorLogs.filter(l => logFilter === 'ALL' || l.type === logFilter).length === 0 && (
                  <div className="py-6 text-center text-[#869397] font-mono text-xs">
                    No log events match the active filter.
                  </div>
                )}
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
              {advisories.map((advisory) => (
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
