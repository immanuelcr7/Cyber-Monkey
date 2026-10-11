import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api, {
  getAllIntegrationsStatus,
  getSocAlerts,
  getOsintInvestigations,
  getMalwareJobs,
  getForensicCases,
  getNetworkAssets,
  getAssessments
} from '../services/api';
import Navbar from '../components/Navbar';
import IntegrationsModal from '../components/IntegrationsModal';
import AiCyberAssistantModal from '../components/AiCyberAssistantModal';

const Home = () => {
  const navigate = useNavigate();
  const [backendStatus, setBackendStatus] = useState('checking'); // checking, online, offline
  const [errorDetails, setErrorDetails] = useState('');
  const [integrationsStatus, setIntegrationsStatus] = useState(null);

  // Live activity counts
  const [counts, setCounts] = useState({
    socAlerts: 0,
    pentestAssessments: 0,
    osintInvestigations: 0,
    malwareJobs: 0,
    forensicCases: 0,
    networkAssets: 0
  });

  // Modals
  const [isIntegrationsOpen, setIsIntegrationsOpen] = useState(false);
  const [isAiOpen, setIsAiOpen] = useState(false);

  const checkHealth = async () => {
    setBackendStatus('checking');
    try {
      const response = await api.get('/health');
      if (response.data && response.data.status === 'ok') {
        setBackendStatus('online');
      } else {
        setBackendStatus('offline');
        setErrorDetails('Unexpected response format');
      }
    } catch (error) {
      setBackendStatus('offline');
      setErrorDetails(error.message || 'Connection failed');
    }

    // Load integration and activity summary
    try {
      const [intStatus, soc, osint, malware, forensics, network, pentest] = await Promise.all([
        getAllIntegrationsStatus().catch(() => null),
        getSocAlerts().catch(() => []),
        getOsintInvestigations().catch(() => []),
        getMalwareJobs().catch(() => []),
        getForensicCases().catch(() => []),
        getNetworkAssets().catch(() => []),
        getAssessments().catch(() => [])
      ]);

      setIntegrationsStatus(intStatus);
      setCounts({
        socAlerts: soc.length,
        pentestAssessments: pentest.length,
        osintInvestigations: osint.length,
        malwareJobs: malware.length,
        forensicCases: forensics.length,
        networkAssets: network.length
      });
    } catch {
      // Graceful fallback
    }
  };

  useEffect(() => {
    checkHealth();
  }, []);

  const workspaces = [
    {
      id: 'soc',
      title: 'SOC Analyst',
      tagline: 'Detection, Triage & Incident Response',
      description: 'Real-time security alert triage, Wazuh SIEM telemetry ingestion, severity filtering, incident tracking, and analyst audit logging.',
      status: 'AVAILABLE',
      route: '/soc',
      icon: '🚨',
      accent: 'from-rose-500/20 to-orange-500/10 border-rose-500/30 text-rose-300',
      tagColor: 'bg-rose-500/10 text-rose-300 border-rose-500/20',
      btnColor: 'bg-rose-500 hover:bg-rose-400 text-[#090A0F]',
      tools: [
        { name: 'Wazuh SIEM', connected: integrationsStatus?.wazuh?.status === 'connected' },
        { name: 'Alert Triage', connected: true }
      ],
      metric: `${counts.socAlerts} Alerts Logged`,
      metricLabel: 'Alerts Ingested'
    },
    {
      id: 'pentest',
      title: 'Penetration Testing',
      tagline: 'Authorized Offensive Security',
      description: 'Authorized penetration testing assessments, active target scoping, network port scanning, web application security, and vulnerability discovery.',
      status: 'AVAILABLE',
      route: '/pentest',
      icon: '🎯',
      accent: 'from-teal-500/20 to-indigo-500/10 border-teal-500/30 text-teal-300',
      tagColor: 'bg-teal-500/10 text-teal-300 border-teal-500/20',
      btnColor: 'bg-teal-400 hover:bg-teal-300 text-[#090A0F]',
      tools: [
        { name: 'Nmap', connected: integrationsStatus?.nmap?.status === 'connected' },
        { name: 'Nuclei', connected: true },
        { name: 'Nikto', connected: true }
      ],
      metric: `${counts.pentestAssessments} Assessments`,
      metricLabel: 'Active Pentests'
    },
    {
      id: 'osint',
      title: 'OSINT',
      tagline: 'Public Surface & Perimeter Footprinting',
      description: 'Legitimate open-source intelligence gathering across subdomains, DNS records, public WHOIS/RDAP registration, identity footprints, and Shodan exposures.',
      status: 'AVAILABLE',
      route: '/osint',
      icon: '🌐',
      accent: 'from-cyan-500/20 to-blue-500/10 border-cyan-500/30 text-cyan-300',
      tagColor: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/20',
      btnColor: 'bg-cyan-400 hover:bg-cyan-300 text-[#090A0F]',
      tools: [
        { name: 'Subfinder', connected: integrationsStatus?.subfinder?.status === 'connected' },
        { name: 'DNS Resolver', connected: integrationsStatus?.dns?.status === 'connected' },
        { name: 'theHarvester', connected: integrationsStatus?.theharvester?.status === 'connected' },
        { name: 'Shodan', connected: integrationsStatus?.shodan?.status === 'connected' }
      ],
      metric: `${counts.osintInvestigations} Investigations`,
      metricLabel: 'OSINT Cases'
    },
    {
      id: 'malware',
      title: 'Malware Analysis',
      tagline: 'Safe Static Binary Triage',
      description: 'Isolated static analysis of suspicious executables and documents. Shannon entropy scoring, PE header parsing, printable strings, and IoC extraction.',
      status: 'AVAILABLE',
      route: '/malware-analysis',
      icon: '🦠',
      accent: 'from-emerald-500/20 to-teal-500/10 border-emerald-500/30 text-emerald-300',
      tagColor: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20',
      btnColor: 'bg-emerald-400 hover:bg-emerald-300 text-[#090A0F]',
      tools: [
        { name: 'Static Triage', connected: true },
        { name: 'YARA Scanner', connected: integrationsStatus?.yara?.status === 'connected' },
        { name: 'Isolated Storage', connected: true }
      ],
      metric: `${counts.malwareJobs} Samples`,
      metricLabel: 'Triaged Samples'
    },
    {
      id: 'forensics',
      title: 'Digital Forensics',
      tagline: 'Evidence Preservation & Case Custody',
      description: 'Cryptographic SHA-256 evidence integrity preservation, immutable read-only storage, verifiable chain of custody event logs, and chronological artifact timelines.',
      status: 'AVAILABLE',
      route: '/digital-forensics',
      icon: '🔬',
      accent: 'from-violet-500/20 to-purple-500/10 border-violet-500/30 text-violet-300',
      tagColor: 'bg-violet-500/10 text-violet-300 border-violet-500/20',
      btnColor: 'bg-violet-500 hover:bg-violet-400 text-white',
      tools: [
        { name: 'SHA-256 Engine', connected: true },
        { name: 'Chain of Custody', connected: true },
        { name: 'Timeline Builder', connected: true }
      ],
      metric: `${counts.forensicCases} Cases`,
      metricLabel: 'Forensic Cases'
    },
    {
      id: 'network',
      title: 'Network Monitoring',
      tagline: 'Asset Availability & Telemetry Detection',
      description: 'Authorized asset inventory monitoring, TCP port availability socket probes, latency tracking, network change anomaly detection, and Nmap asset discovery.',
      status: 'AVAILABLE',
      route: '/network-monitoring',
      icon: '📡',
      accent: 'from-blue-500/20 to-indigo-500/10 border-blue-500/30 text-blue-300',
      tagColor: 'bg-blue-500/10 text-blue-300 border-blue-500/20',
      btnColor: 'bg-blue-500 hover:bg-blue-400 text-white',
      tools: [
        { name: 'TCP Socket Probe', connected: true },
        { name: 'Nmap Discovery', connected: integrationsStatus?.nmap?.status === 'connected' },
        { name: 'Zeek / Suricata', connected: integrationsStatus?.zeek?.status === 'connected' }
      ],
      metric: `${counts.networkAssets} Assets`,
      metricLabel: 'Monitored Assets'
    }
  ];

  return (
    <div className="min-h-screen flex flex-col justify-between p-4 md:p-8 relative overflow-hidden bg-[#090A0F] text-slate-100">
      
      {/* Decorative cyber grid/shapes */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] rounded-full bg-teal-500/10 blur-[130px] pointer-events-none"></div>
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full bg-indigo-500/10 blur-[130px] pointer-events-none"></div>
      
      {/* Top Navbar */}
      <Navbar
        onOpenAi={() => setIsAiOpen(true)}
        onOpenIntegrations={() => setIsIntegrationsOpen(true)}
      />

      {/* Main Content Hero */}
      <main className="w-full max-w-7xl mx-auto my-auto flex flex-col items-center text-center z-10 py-6">
        
        {/* Brand Tagline Badge */}
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-xs font-semibold uppercase tracking-widest mb-4 animate-pulse">
          ⚡ One Platform. Every Cybersecurity Professional.
        </div>

        {/* Brand Headings */}
        <h1 className="text-5xl md:text-7xl font-black tracking-tight mb-3">
          <span className="bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-100 to-teal-400">
            Cyber Monkey OS
          </span>
        </h1>
        
        <p className="text-base md:text-xl font-medium tracking-wide text-slate-300 max-w-2xl mb-8">
          Unified AI-Powered Cybersecurity Operating System with 6 Specialized Workspaces.
        </p>

        {/* Diagnostics & Quick Actions Bar */}
        <div className="w-full max-w-3xl mb-10 flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-2xl cyber-glass border border-white/10">
          <div className="flex items-center gap-3">
            <span className={`w-3 h-3 rounded-full ${backendStatus === 'online' ? 'bg-teal-400 animate-pulse' : (backendStatus === 'checking' ? 'bg-indigo-400 animate-spin' : 'bg-rose-400')}`} />
            <div className="text-left">
              <div className="text-xs font-bold text-white uppercase tracking-wider">
                API Backend: {backendStatus === 'online' ? 'Connected & Operational' : (backendStatus === 'checking' ? 'Resolving...' : 'Offline')}
              </div>
              <span className="font-mono text-[11px] text-slate-400">
                FastAPI ASGI Server • SQLite / Postgres
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsIntegrationsOpen(true)}
              className="px-3 py-1.5 text-xs rounded-lg border border-white/10 hover:border-teal-500/30 bg-white/5 hover:bg-white/10 text-slate-200 transition cursor-pointer flex items-center gap-1.5"
            >
              <span>🔌</span>
              <span>Tool Health</span>
            </button>
            <button
              onClick={() => setIsAiOpen(true)}
              className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-gradient-to-r from-teal-400 to-indigo-500 text-[#090A0F] shadow transition cursor-pointer flex items-center gap-1.5"
            >
              <span>🧠</span>
              <span>Launch AI</span>
            </button>
          </div>
        </div>

        {/* Six Cybersecurity Workspaces Grid */}
        <section className="w-full text-left">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-xl font-bold text-white">Cybersecurity Workspaces</h3>
              <p className="text-xs text-slate-400">
                Select your mission profile to access specialized tooling and analysis engines.
              </p>
            </div>
            <span className="px-2.5 py-1 rounded-full text-[10px] font-mono uppercase bg-teal-500/10 text-teal-300 border border-teal-500/20">
              6 / 6 Workspaces Active
            </span>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {workspaces.map((ws) => (
              <div
                key={ws.id}
                onClick={() => navigate(ws.route)}
                className="p-6 rounded-2xl cyber-glass relative overflow-hidden flex flex-col justify-between transition-all duration-300 hover:border-teal-500/30 hover:shadow-2xl hover:shadow-teal-500/5 group cursor-pointer border border-white/5"
              >
                {/* Accent top stripe */}
                <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-teal-400 to-indigo-500"></div>

                <div>
                  <div className="flex items-start justify-between mb-4">
                    <div className="text-3xl p-3 bg-white/5 rounded-2xl border border-white/5 group-hover:scale-110 transition-transform">
                      {ws.icon}
                    </div>
                    <span className={`px-2.5 py-0.5 text-[10px] font-bold tracking-wider rounded-full uppercase border ${ws.tagColor}`}>
                      {ws.status}
                    </span>
                  </div>

                  <h4 className="text-xl font-bold text-white group-hover:text-teal-300 transition-colors">
                    {ws.title}
                  </h4>
                  <div className="text-xs font-medium text-indigo-300/80 mb-2 font-mono">
                    {ws.tagline}
                  </div>
                  
                  <p className="text-slate-400 text-xs leading-relaxed mb-4 line-clamp-3">
                    {ws.description}
                  </p>
                </div>

                <div>
                  {/* Tool Integration Badges */}
                  <div className="mb-4 pt-3 border-t border-white/5 flex flex-wrap gap-1.5">
                    {ws.tools.map((t, idx) => (
                      <span
                        key={idx}
                        className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                          t.connected
                            ? 'bg-teal-500/10 text-teal-300 border border-teal-500/20'
                            : 'bg-white/5 text-slate-500 border border-white/5'
                        }`}
                      >
                        {t.name}
                      </span>
                    ))}
                  </div>

                  {/* Activity Metric and Launch Button */}
                  <div className="flex items-center justify-between pt-2">
                    <span className="font-mono text-xs text-slate-300 font-semibold">
                      {ws.metric}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(ws.route);
                      }}
                      className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg ${ws.btnColor} shadow transition group-hover:scale-105 cursor-pointer`}
                    >
                      Enter &rarr;
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

      </main>

      {/* Footer */}
      <footer className="w-full max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 border-t border-white/5 pt-6 mt-8 z-10 gap-3">
        <div>
          &copy; {new Date().getFullYear()} Cyber Monkey OS. One Platform. Every Cybersecurity Professional.
        </div>
        <div className="flex items-center gap-4">
          <button onClick={() => setIsIntegrationsOpen(true)} className="hover:text-teal-400 transition cursor-pointer">
            Tool Integrations
          </button>
          <button onClick={() => setIsAiOpen(true)} className="hover:text-teal-400 transition cursor-pointer">
            AI Assistant
          </button>
          <span className="text-slate-600">|</span>
          <span className="font-mono text-[11px] text-slate-400">v2.0 Full-Spectrum Suite</span>
        </div>
      </footer>

      {/* MODALS */}
      <IntegrationsModal
        isOpen={isIntegrationsOpen}
        onClose={() => setIsIntegrationsOpen(false)}
      />

      <AiCyberAssistantModal
        isOpen={isAiOpen}
        onClose={() => setIsAiOpen(false)}
        initialWorkspace="soc"
      />
    </div>
  );
};

export default Home;
