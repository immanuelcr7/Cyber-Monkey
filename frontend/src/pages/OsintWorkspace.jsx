import React, { useState, useEffect } from 'react';
import {
  getOsintToolsStatus,
  getOsintInvestigations,
  createOsintInvestigation,
  getOsintInvestigation,
  runOsintScan,
  addOsintNote,
  exportOsintInvestigation
} from '../services/api';
import Navbar from '../components/Navbar';
import AiCyberAssistantModal from '../components/AiCyberAssistantModal';
import IntegrationsModal from '../components/IntegrationsModal';

// IP and Domain validation helpers
const isIpv4OrCidr = (val) => {
  if (!val) return false;
  const trimmed = val.trim();
  const cidrParts = trimmed.split('/');
  if (cidrParts.length > 2) return false;
  const ip = cidrParts[0];
  const ipParts = ip.split('.');
  if (ipParts.length !== 4) return false;
  for (const part of ipParts) {
    if (!/^\d+$/.test(part)) return false;
    const num = parseInt(part, 10);
    if (num < 0 || num > 255) return false;
  }
  if (cidrParts.length === 2) {
    if (!/^\d+$/.test(cidrParts[1])) return false;
    const mask = parseInt(cidrParts[1], 10);
    if (mask < 0 || mask > 32) return false;
  }
  return true;
};

const isPrivateIp = (val) => {
  if (!val) return false;
  const ip = val.trim().split('/')[0];
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 127.0.0.0/8
  if (parts[0] === 127) return true;
  return false;
};

const isValidDomainName = (val) => {
  if (!val) return false;
  let clean = val.trim().replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
  if (isIpv4OrCidr(clean)) return false;
  const regex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return regex.test(clean);
};

const OsintWorkspace = () => {
  const [toolsStatus, setToolsStatus] = useState(null);
  const [investigations, setInvestigations] = useState([]);
  const [selectedInv, setSelectedInv] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scanRunning, setScanRunning] = useState(false);
  const [scanMessage, setScanMessage] = useState('');
  const [filterType, setFilterType] = useState('');

  // Modals & form processing
  const [isNewInvOpen, setIsNewInvOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [modalError, setModalError] = useState('');
  const [successBanner, setSuccessBanner] = useState('');
  const [isAiOpen, setIsAiOpen] = useState(false);
  const [isIntegrationsOpen, setIsIntegrationsOpen] = useState(false);
  const [newNoteText, setNewNoteText] = useState('');

  // Investigation form
  const [invForm, setInvForm] = useState({
    title: '',
    target: '',
    target_type: 'domain',
    scope_description: '',
    investigation_purpose: '',
    authorization_confirmed: false
  });

  const loadInitial = async () => {
    setLoading(true);
    try {
      const [tools, list] = await Promise.all([
        getOsintToolsStatus().catch(() => ({})),
        getOsintInvestigations()
      ]);
      setToolsStatus(tools);
      setInvestigations(list);
      if (list.length > 0) {
        loadInvestigationDetail(list[0].id);
      }
    } catch (err) {
      console.error('Error loading OSINT data:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadInvestigationDetail = async (id) => {
    try {
      const detail = await getOsintInvestigation(id);
      setSelectedInv(detail);
    } catch (err) {
      console.error('Failed to load investigation details:', err);
    }
  };

  useEffect(() => {
    loadInitial();
  }, []);

  const handleCreateInvestigation = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    setModalError('');

    const title = invForm.title.trim();
    const rawTarget = invForm.target.trim();
    const purpose = invForm.investigation_purpose.trim();
    const targetType = invForm.target_type;

    if (!title) {
      setModalError('Please provide an Investigation Title.');
      return;
    }

    if (!rawTarget) {
      setModalError('Please specify a Target Domain or IP address.');
      return;
    }

    // Input target validation by type
    if (targetType === 'ip') {
      if (!isIpv4OrCidr(rawTarget)) {
        setModalError(`Invalid IPv4 address or CIDR format: "${rawTarget}". Example: 192.168.1.40 or 10.0.0.0/24`);
        return;
      }
    } else if (targetType === 'domain') {
      const cleanDomain = rawTarget.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
      if (isIpv4OrCidr(cleanDomain)) {
        // Auto-switch to ip
      } else if (!isValidDomainName(cleanDomain)) {
        setModalError(`Invalid domain format: "${rawTarget}". Example: cybermonkey.io or sub.example.com`);
        return;
      }
    } else if (targetType === 'organization') {
      if (rawTarget.length < 2) {
        setModalError('Organization name must contain at least 2 characters.');
        return;
      }
    }

    if (purpose.length < 3) {
      setModalError('Please define a legitimate investigation purpose (at least 3 characters).');
      return;
    }

    if (!invForm.authorization_confirmed) {
      setModalError('You must check the authorization confirmation to comply with legal scoping policies.');
      return;
    }

    setIsSubmitting(true);
    try {
      const payload = {
        title,
        target: rawTarget.replace(/^https?:\/\//i, '').split('/')[0],
        target_type: targetType,
        scope_description: invForm.scope_description.trim() || undefined,
        investigation_purpose: purpose,
        authorization_confirmed: true
      };

      const created = await createOsintInvestigation(payload);
      if (!created || !created.id) {
        throw new Error('Server returned an invalid investigation response.');
      }

      // Add to list and immediately select
      setInvestigations((prev) => [created, ...prev]);
      setSelectedInv(created);
      setIsNewInvOpen(false);
      setSuccessBanner(`Investigation "${created.title}" successfully created! Select an active intelligence tool below to begin.`);
      setModalError('');
      setInvForm({
        title: '',
        target: '',
        target_type: 'domain',
        scope_description: '',
        investigation_purpose: '',
        authorization_confirmed: false
      });

      // Fetch fresh full detail for the new investigation
      loadInvestigationDetail(created.id);
    } catch (err) {
      console.error('Failed to create investigation:', err);
      let errorText = 'Failed to create investigation.';
      if (err.response?.data?.detail) {
        if (Array.isArray(err.response.data.detail)) {
          errorText = err.response.data.detail
            .map((d) => `${d.loc ? d.loc[d.loc.length - 1] + ': ' : ''}${d.msg}`)
            .join(', ');
        } else if (typeof err.response.data.detail === 'string') {
          errorText = err.response.data.detail;
        } else {
          errorText = JSON.stringify(err.response.data.detail);
        }
      } else if (err.message) {
        errorText = err.message;
      }
      setModalError(errorText);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRunTool = async (toolName) => {
    if (!selectedInv) return;
    setScanRunning(true);
    setScanMessage(`Executing ${toolName} against ${selectedInv.target}...`);
    try {
      const res = await runOsintScan(selectedInv.id, {
        tool: toolName,
        authorization_confirmed: true
      });
      setScanMessage(`${toolName} execution successful.`);
      loadInvestigationDetail(selectedInv.id);
    } catch (err) {
      setScanMessage(err.response?.data?.detail || err.message || `${toolName} execution failed.`);
    } finally {
      setScanRunning(false);
    }
  };

  const handleAddNote = async () => {
    if (!newNoteText.trim() || !selectedInv) return;
    try {
      const note = await addOsintNote(selectedInv.id, {
        author: 'OSINT Researcher',
        note: newNoteText.trim()
      });
      setSelectedInv({
        ...selectedInv,
        notes: [...(selectedInv.notes || []), note]
      });
      setNewNoteText('');
    } catch (err) {
      alert('Failed to add note: ' + err.message);
    }
  };

  const handleExportJson = async () => {
    if (!selectedInv) return;
    try {
      const pkg = await exportOsintInvestigation(selectedInv.id);
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(pkg, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `OSINT_${selectedInv.target}_export.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } catch (err) {
      alert('Failed to export: ' + err.message);
    }
  };

  const filteredRecords = selectedInv?.records?.filter(r => {
    if (!filterType) return true;
    return r.record_type === filterType || r.tool === filterType;
  }) || [];

  return (
    <div className="min-h-screen p-4 md:p-8 relative bg-[#090A0F] text-slate-100 flex flex-col justify-between">
      {/* Background cyber glow */}
      <div className="absolute top-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-cyan-500/5 blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-indigo-500/10 blur-[120px] pointer-events-none"></div>

      <div className="max-w-7xl w-full mx-auto z-10 flex-1">
        <Navbar
          activeWorkspaceTitle="OSINT Workspace"
          onOpenAi={() => setIsAiOpen(true)}
          onOpenIntegrations={() => setIsIntegrationsOpen(true)}
        />

        {/* Success Banner */}
        {successBanner && (
          <div className="mb-4 p-4 rounded-xl bg-teal-500/10 border border-teal-500/30 text-teal-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-base">✅</span>
              <span>{successBanner}</span>
            </div>
            <button
              onClick={() => setSuccessBanner('')}
              className="text-teal-400 hover:text-white font-bold ml-4 cursor-pointer"
            >
              &times;
            </button>
          </div>
        )}

        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 text-xs font-semibold uppercase tracking-wider mb-2">
              🌐 Open Source Intelligence
            </div>
            <h1 className="text-3xl md:text-4xl font-black bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-100 to-cyan-400">
              OSINT Workspace
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Authorized public intelligence gathering across subdomains, DNS, WHOIS/RDAP, identities, and Shodan footprints.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                setModalError('');
                setIsNewInvOpen(true);
              }}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-cyan-400 hover:bg-cyan-300 text-[#090A0F] shadow-lg shadow-cyan-400/20 transition cursor-pointer flex items-center gap-1.5"
            >
              <span>+</span>
              <span>New Investigation</span>
            </button>
          </div>
        </div>

        {/* Tool Availability Ribbon */}
        <div className="p-4 rounded-2xl cyber-glass border border-white/10 mb-6 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-4 flex-wrap">
            <span className="font-bold uppercase tracking-wider text-slate-400 text-[11px]">Recon Engines:</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${toolsStatus?.subfinder?.available ? 'bg-teal-500/10 text-teal-300' : 'bg-white/5 text-slate-400'}`}>
              Subfinder: {toolsStatus?.subfinder?.available ? 'Ready' : 'CLI Only'}
            </span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${toolsStatus?.dns?.available ? 'bg-teal-500/10 text-teal-300' : 'bg-white/5 text-slate-400'}`}>
              DNS Resolver: {toolsStatus?.dns?.available ? 'Active' : 'Unreachable'}
            </span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${toolsStatus?.whois_rdap?.available ? 'bg-teal-500/10 text-teal-300' : 'bg-white/5 text-slate-400'}`}>
              RDAP / WHOIS: Active
            </span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${toolsStatus?.shodan?.configured ? 'bg-teal-500/10 text-teal-300' : 'bg-amber-500/10 text-amber-300'}`}>
              Shodan: {toolsStatus?.shodan?.configured ? 'API Key Configured' : 'No Key'}
            </span>
          </div>

          <button
            onClick={() => setIsIntegrationsOpen(true)}
            className="text-cyan-400 hover:underline text-[11px] cursor-pointer"
          >
            Configure Engine Keys &rarr;
          </button>
        </div>

        {/* Workspace Main Split */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Left Column: Investigations List */}
          <div className="cyber-glass rounded-2xl border border-white/10 p-4 space-y-3 h-fit">
            <div className="flex items-center justify-between pb-2 border-b border-white/10">
              <h3 className="font-bold text-sm text-white">Investigations ({investigations.length})</h3>
              <button
                onClick={() => {
                  setModalError('');
                  setIsNewInvOpen(true);
                }}
                className="text-cyan-400 hover:text-cyan-300 text-xs font-semibold cursor-pointer"
              >
                + Add
              </button>
            </div>

            {investigations.length === 0 ? (
              <div className="py-8 text-center text-slate-500 text-xs">
                No investigations created yet.
              </div>
            ) : (
              <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                {investigations.map((inv) => {
                  const isSelected = selectedInv?.id === inv.id;
                  return (
                    <div
                      key={inv.id}
                      onClick={() => loadInvestigationDetail(inv.id)}
                      className={`p-3 rounded-xl border transition cursor-pointer ${
                        isSelected
                          ? 'bg-cyan-500/10 border-cyan-500/30 text-white'
                          : 'bg-white/[0.02] border-white/5 text-slate-300 hover:bg-white/5'
                      }`}
                    >
                      <h4 className="font-semibold text-xs line-clamp-1">{inv.title}</h4>
                      <div className="flex items-center justify-between text-[10px] text-slate-400 mt-1">
                        <span className="font-mono text-cyan-300">{inv.target}</span>
                        <span className="bg-white/5 px-1.5 py-0.5 rounded">{inv.records_count || 0} records</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Right Column: Active Investigation Details & Execution */}
          <div className="lg:col-span-3 space-y-6">
            {selectedInv ? (
              <>
                {/* Active Target Banner & Action Bar */}
                <div className="cyber-glass rounded-2xl border border-white/10 p-6 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                          {selectedInv.target_type}
                        </span>
                        <h2 className="text-xl font-bold text-white">{selectedInv.title}</h2>
                      </div>
                      <p className="font-mono text-xs text-cyan-300 mt-1">
                        Target: <strong>{selectedInv.target}</strong>
                      </p>
                      <p className="text-xs text-slate-400 mt-1 italic">
                        "{selectedInv.investigation_purpose}"
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => {
                          setIsAiOpen(true);
                        }}
                        className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-teal-400 to-indigo-500 text-[#090A0F] shadow cursor-pointer flex items-center gap-1.5"
                      >
                        <span>🧠</span>
                        <span>AI Surface Synthesis</span>
                      </button>
                      <button
                        onClick={handleExportJson}
                        className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-white/10 hover:bg-white/15 text-white transition cursor-pointer flex items-center gap-1.5"
                      >
                        <span>⬇️</span>
                        <span>Export Package</span>
                      </button>
                    </div>
                  </div>

                  {/* Private RFC 1918 IP Context */}
                  {isPrivateIp(selectedInv.target) && (
                    <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs flex items-start gap-3">
                      <span className="text-lg">🏢</span>
                      <div>
                        <div className="font-bold text-amber-100">Local Network Target (RFC 1918 Private IP Address)</div>
                        <p className="text-[11px] text-amber-300/80 mt-0.5">
                          Target <strong>{selectedInv.target}</strong> is in private local network space.
                          Public registries (Shodan, Subfinder, theHarvester) only track publicly routable internet assets.
                          RDAP lookup will provide RFC 1918 reservation details. For port & service discovery, use <strong>Network Monitoring</strong> or <strong>Penetration Testing</strong>.
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Tool Action Buttons with Execution Separation Notice */}
                  <div className="pt-4 border-t border-white/10">
                    <div className="flex items-center justify-between mb-2">
                      <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                        ⚡ Active Reconnaissance Scans (Individually Executed)
                      </label>
                      <span className="text-[10px] text-slate-500">
                        Investigations establish scope; triggers are isolated per tool
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button
                        onClick={() => handleRunTool('whois_rdap')}
                        disabled={scanRunning}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium bg-white/5 hover:bg-cyan-500/10 border border-white/10 hover:border-cyan-500/30 text-slate-200 hover:text-cyan-300 transition cursor-pointer disabled:opacity-50"
                        title="Query RFC 7480 RDAP / WHOIS registry"
                      >
                        🔎 RDAP / WHOIS Lookup
                      </button>
                      <button
                        onClick={() => handleRunTool('dns')}
                        disabled={scanRunning || isIpv4OrCidr(selectedInv.target)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
                          isIpv4OrCidr(selectedInv.target)
                            ? 'bg-white/5 border-white/5 text-slate-500'
                            : 'bg-white/5 hover:bg-cyan-500/10 border-white/10 hover:border-cyan-500/30 text-slate-200 hover:text-cyan-300'
                        }`}
                        title={isIpv4OrCidr(selectedInv.target) ? 'Domain target required for forward DNS lookup' : 'Query DNS records'}
                      >
                        📡 DNS Records {isIpv4OrCidr(selectedInv.target) && <span className="text-[9px] text-slate-500">(Domain Only)</span>}
                      </button>
                      <button
                        onClick={() => handleRunTool('subfinder')}
                        disabled={scanRunning || isIpv4OrCidr(selectedInv.target) || !toolsStatus?.subfinder?.available}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium bg-white/5 hover:bg-cyan-500/10 border border-white/10 hover:border-cyan-500/30 text-slate-200 hover:text-cyan-300 transition cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                        title={isIpv4OrCidr(selectedInv.target) ? 'Domain target required' : !toolsStatus?.subfinder?.available ? 'Subfinder CLI not installed on host' : 'Run Subfinder passive reconnaissance'}
                      >
                        🌐 Subfinder {!toolsStatus?.subfinder?.available && <span className="text-[9px] text-slate-500">(CLI Unavailable)</span>}
                      </button>
                      <button
                        onClick={() => handleRunTool('theharvester')}
                        disabled={scanRunning || isIpv4OrCidr(selectedInv.target) || !toolsStatus?.theharvester?.available}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium bg-white/5 hover:bg-cyan-500/10 border border-white/10 hover:border-cyan-500/30 text-slate-200 hover:text-cyan-300 transition cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                        title={isIpv4OrCidr(selectedInv.target) ? 'Domain target required' : !toolsStatus?.theharvester?.available ? 'theHarvester CLI not installed on host' : 'Run theHarvester email & host reconnaissance'}
                      >
                        ✉️ theHarvester {!toolsStatus?.theharvester?.available && <span className="text-[9px] text-slate-500">(CLI Unavailable)</span>}
                      </button>
                      <button
                        onClick={() => handleRunTool('shodan')}
                        disabled={scanRunning || isPrivateIp(selectedInv.target) || !toolsStatus?.shodan?.configured}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium bg-white/5 hover:bg-cyan-500/10 border border-white/10 hover:border-cyan-500/30 text-slate-200 hover:text-cyan-300 transition cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                        title={isPrivateIp(selectedInv.target) ? 'Shodan cannot query private local RFC 1918 IPs' : !toolsStatus?.shodan?.configured ? 'Shodan API key is not configured in .env' : 'Query Shodan intelligence'}
                      >
                        ⚡ Shodan {isPrivateIp(selectedInv.target) ? <span className="text-[9px] text-amber-400">(Public IPs Only)</span> : !toolsStatus?.shodan?.configured ? <span className="text-[9px] text-slate-500">(No API Key)</span> : ''}
                      </button>
                    </div>

                    {scanMessage && (
                      <div className="mt-3 text-xs font-mono text-cyan-300 bg-cyan-500/10 p-2.5 rounded-lg border border-cyan-500/20 flex items-center justify-between">
                        <span>{scanMessage}</span>
                        {scanRunning && <span className="animate-spin text-sm">⏳</span>}
                      </div>
                    )}
                  </div>
                </div>

                {/* Collected Intelligence Feed */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="font-bold text-base text-white">
                      Aggregated Intelligence Records ({filteredRecords.length})
                    </h3>

                    {/* Filter Tabs */}
                    <div className="flex gap-1.5">
                      <button
                        onClick={() => setFilterType('')}
                        className={`px-2.5 py-1 rounded text-xs transition ${
                          !filterType ? 'bg-white/20 text-white font-bold' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        All
                      </button>
                      <button
                        onClick={() => setFilterType('whois')}
                        className={`px-2.5 py-1 rounded text-xs transition ${
                          filterType === 'whois' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        WHOIS
                      </button>
                      <button
                        onClick={() => setFilterType('dns_record')}
                        className={`px-2.5 py-1 rounded text-xs transition ${
                          filterType === 'dns_record' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        DNS
                      </button>
                      <button
                        onClick={() => setFilterType('subdomain')}
                        className={`px-2.5 py-1 rounded text-xs transition ${
                          filterType === 'subdomain' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Subdomains
                      </button>
                      <button
                        onClick={() => setFilterType('shodan_host')}
                        className={`px-2.5 py-1 rounded text-xs transition ${
                          filterType === 'shodan_host' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Shodan
                      </button>
                    </div>
                  </div>

                  {filteredRecords.length === 0 ? (
                    <div className="py-12 text-center cyber-glass rounded-2xl border border-white/5 p-6">
                      <p className="text-xs text-slate-500">
                        No intelligence records collected yet. Run a tool from the action bar above to start footprinting.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {filteredRecords.map((rec) => (
                        <div key={rec.id} className="p-4 rounded-xl cyber-glass border border-white/10 space-y-2">
                          <div className="flex items-center justify-between text-xs pb-2 border-b border-white/5">
                            <div className="flex items-center gap-2">
                              <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                                {rec.tool}
                              </span>
                              <span className="text-slate-300 font-medium capitalize">
                                {rec.record_type.replace('_', ' ')}
                              </span>
                              <span className="px-1.5 py-0.2 rounded text-[9px] bg-teal-500/10 text-teal-300 border border-teal-500/20">
                                Live Retrieved
                              </span>
                            </div>
                            <span className="text-[10px] text-slate-500 font-mono">
                              Collected: {new Date(rec.collection_timestamp).toLocaleString()}
                            </span>
                          </div>

                          {/* Data Viewer */}
                          <div className="text-xs font-mono bg-black/40 p-3 rounded-lg border border-white/5 overflow-x-auto max-h-48 text-slate-300">
                            <pre className="whitespace-pre-wrap">{JSON.stringify(rec.data, null, 2)}</pre>
                          </div>

                          {rec.source_url && (
                            <div className="text-[10px] text-slate-500 truncate">
                              Source Reference: <span className="text-cyan-400">{rec.source_url}</span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Notes Section */}
                <div className="cyber-glass rounded-2xl border border-white/10 p-5 space-y-3">
                  <h3 className="font-bold text-sm text-white">Researcher Investigation Notes</h3>
                  <div className="space-y-2 max-h-36 overflow-y-auto">
                    {selectedInv.notes?.map((n) => (
                      <div key={n.id} className="p-2.5 rounded-lg bg-white/[0.02] border border-white/5 text-xs">
                        <div className="flex justify-between text-[10px] text-slate-400 mb-0.5">
                          <strong>{n.author}</strong>
                          <span>{new Date(n.created_at).toLocaleString()}</span>
                        </div>
                        <p className="text-slate-200">{n.note}</p>
                      </div>
                    ))}
                  </div>

                  <div className="flex gap-2 pt-2 border-t border-white/5">
                    <input
                      type="text"
                      placeholder="Add research note..."
                      value={newNoteText}
                      onChange={(e) => setNewNoteText(e.target.value)}
                      className="flex-1 px-3 py-1.5 bg-white/5 border border-white/10 rounded-lg text-xs text-white focus:outline-none"
                    />
                    <button
                      onClick={handleAddNote}
                      className="px-4 py-1.5 rounded-lg text-xs bg-cyan-500 hover:bg-cyan-400 text-[#090A0F] font-bold cursor-pointer"
                    >
                      Add Note
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <div className="py-24 text-center cyber-glass rounded-2xl border border-white/5 p-8">
                <span className="text-4xl block mb-2">🌐</span>
                <h4 className="font-bold text-slate-300">Select or Create an Investigation</h4>
                <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1 mb-4">
                  OSINT investigations maintain authorized boundaries and store timestamped evidence artifacts.
                </p>
                <button
                  onClick={() => setIsNewInvOpen(true)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-cyan-400 hover:bg-cyan-300 text-[#090A0F] cursor-pointer"
                >
                  Create Investigation
                </button>
              </div>
            )}
          </div>
        </div>

      </div>

      {/* NEW INVESTIGATION MODAL */}
      {isNewInvOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-[#0e1017] border border-white/10 rounded-2xl p-6 relative">
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
              <h3 className="font-bold text-base text-white">Create Authorized OSINT Investigation</h3>
              <button
                onClick={() => {
                  setModalError('');
                  setIsNewInvOpen(false);
                }}
                className="text-slate-400 hover:text-white text-lg font-bold cursor-pointer"
              >
                &times;
              </button>
            </div>

            {modalError && (
              <div className="mb-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-2">
                <span className="text-base font-bold">⚠️</span>
                <span className="flex-1 leading-relaxed">{modalError}</span>
              </div>
            )}

            <form onSubmit={handleCreateInvestigation} className="space-y-4">
              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">
                  Investigation Title
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Perimeter Domain & Cloud Footprint Assessment"
                  value={invForm.title}
                  onChange={(e) => {
                    setInvForm({ ...invForm, title: e.target.value });
                    if (modalError) setModalError('');
                  }}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">
                    Target Domain or IP
                  </label>
                  <input
                    type="text"
                    required
                    placeholder={
                      invForm.target_type === 'ip'
                        ? 'e.g., 192.168.1.40 or 10.0.0.0/24'
                        : invForm.target_type === 'organization'
                        ? 'e.g., Acme Cybersecurity Corp'
                        : 'e.g., cybermonkey.io or sub.example.com'
                    }
                    value={invForm.target}
                    onChange={(e) => {
                      setInvForm({ ...invForm, target: e.target.value });
                      if (modalError) setModalError('');
                    }}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-cyan-400 font-mono text-[11px]"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">
                    Target Type
                  </label>
                  <select
                    value={invForm.target_type}
                    onChange={(e) => setInvForm({ ...invForm, target_type: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  >
                    <option value="domain" className="bg-[#0e1017]">Domain</option>
                    <option value="ip" className="bg-[#0e1017]">IPv4 / Subnet</option>
                    <option value="organization" className="bg-[#0e1017]">Organization</option>
                  </select>
                </div>
              </div>

              {isPrivateIp(invForm.target) && (
                <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-start gap-2">
                  <span className="text-base">🏢</span>
                  <div className="text-[11px] leading-relaxed">
                    <span className="font-bold text-amber-200">RFC 1918 Private IP Detected:</span>{' '}
                    Target is in internal network space. Public OSINT tools (Shodan, theHarvester) cannot scan private IPs. RDAP lookup will show RFC 1918 reservation info, and local asset monitoring is supported via Network Monitoring.
                  </div>
                </div>
              )}

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">
                  Legitimate Investigation Purpose
                </label>
                <textarea
                  rows={2}
                  required
                  placeholder="State the legitimate organizational or authorized assessment purpose..."
                  value={invForm.investigation_purpose}
                  onChange={(e) => {
                    setInvForm({ ...invForm, investigation_purpose: e.target.value });
                    if (modalError) setModalError('');
                  }}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="p-3 rounded-xl bg-cyan-500/5 border border-cyan-500/20 flex items-start gap-3">
                <input
                  type="checkbox"
                  id="auth_check"
                  checked={invForm.authorization_confirmed}
                  onChange={(e) => {
                    setInvForm({ ...invForm, authorization_confirmed: e.target.checked });
                    if (modalError) setModalError('');
                  }}
                  className="mt-0.5 rounded text-cyan-400 focus:ring-0 cursor-pointer"
                />
                <label htmlFor="auth_check" className="text-xs text-slate-300 cursor-pointer">
                  I confirm that this intelligence collection targets authorized assets and adheres to legal scoping policies.
                </label>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setModalError('');
                    setIsNewInvOpen(false);
                  }}
                  className="px-4 py-2 rounded-xl text-xs bg-white/10 hover:bg-white/15 text-white cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-cyan-400 hover:bg-cyan-300 text-[#090A0F] disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5 cursor-pointer shadow-md transition"
                >
                  {isSubmitting && <span className="animate-spin text-sm">⏳</span>}
                  <span>{isSubmitting ? 'Starting Investigation...' : 'Start Investigation'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* AI ASSISTANT MODAL */}
      <AiCyberAssistantModal
        isOpen={isAiOpen}
        onClose={() => setIsAiOpen(false)}
        initialWorkspace="osint"
        initialEvidence={selectedInv ? {
          target: selectedInv.target,
          target_type: selectedInv.target_type,
          records_count: selectedInv.records?.length || 0,
          sample_records: selectedInv.records?.slice(0, 5) || []
        } : null}
        initialTask="summarize"
      />

      {/* INTEGRATIONS MODAL */}
      <IntegrationsModal
        isOpen={isIntegrationsOpen}
        onClose={() => setIsIntegrationsOpen(false)}
      />
    </div>
  );
};

export default OsintWorkspace;
