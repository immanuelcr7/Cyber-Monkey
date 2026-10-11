import React, { useState, useEffect } from 'react';
import {
  getSocStatus,
  syncWazuhAlerts,
  getSocAlerts,
  updateSocAlert,
  addSocAlertNote,
  createSocAlert,
  getSocIncidents,
  createSocIncident,
  updateSocIncident,
  addSocIncidentNote,
  getSocAuditLogs,
} from '../services/api';
import Navbar from '../components/Navbar';
import AiCyberAssistantModal from '../components/AiCyberAssistantModal';
import IntegrationsModal from '../components/IntegrationsModal';

const SocWorkspace = () => {
  const [wazuhStatus, setWazuhStatus] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // View state: 'alerts' | 'incidents' | 'ingest' | 'audit'
  const [activeTab, setActiveTab] = useState('alerts');

  // Filters
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  // Selected for Details
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);

  // Modals
  const [isAiOpen, setIsAiOpen] = useState(false);
  const [aiEvidence, setAiEvidence] = useState(null);
  const [isIntegrationsOpen, setIsIntegrationsOpen] = useState(false);
  const [isNewIncidentOpen, setIsNewIncidentOpen] = useState(false);

  // Form states
  const [newNoteText, setNewNoteText] = useState('');
  const [syncLoading, setSyncLoading] = useState(false);
  const [syncMessage, setSyncMessage] = useState('');

  // Ingest Form
  const [ingestForm, setIngestForm] = useState({
    rule_id: '100201',
    rule_description: 'Anomalous SSH login attempts detected from untrusted subnet',
    rule_level: 8,
    severity: 'high',
    source: 'Wazuh / Syslog',
    host_name: 'srv-db-prod-01',
    host_ip: '10.0.4.15',
    evidence: 'sshd: Failed password for root from 198.51.100.22 port 54224'
  });

  // Incident Form
  const [incidentForm, setIncidentForm] = useState({
    title: '',
    description: '',
    severity: 'high',
    category: 'Unauthorized Access',
    assigned_to: 'Tier 2 Analyst'
  });

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [wazuh, alertList, incList, logs] = await Promise.all([
        getSocStatus().catch(() => ({ configured: false, connected: false, message: 'Status endpoint offline' })),
        getSocAlerts({ severity: severityFilter || undefined, status: statusFilter || undefined, q: searchQuery || undefined }),
        getSocIncidents(),
        getSocAuditLogs().catch(() => [])
      ]);
      setWazuhStatus(wazuh);
      setAlerts(alertList);
      setIncidents(incList);
      setAuditLogs(logs);
    } catch (err) {
      setError(err.message || 'Failed to load SOC telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [severityFilter, statusFilter, searchQuery]);

  const handleSyncWazuh = async () => {
    setSyncLoading(true);
    setSyncMessage('');
    try {
      const res = await syncWazuhAlerts();
      setSyncMessage(res.message || 'Sync completed.');
      loadData();
    } catch (err) {
      setSyncMessage(err.response?.data?.detail || err.message || 'Wazuh sync failed.');
    } finally {
      setSyncLoading(false);
    }
  };

  const handleUpdateAlertStatus = async (alertId, newStatus) => {
    try {
      const updated = await updateSocAlert(alertId, { status: newStatus });
      setAlerts(alerts.map(a => a.id === alertId ? updated : a));
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert(updated);
      }
    } catch (err) {
      alert('Failed to update alert: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleAddAlertNote = async () => {
    if (!newNoteText.trim() || !selectedAlert) return;
    try {
      const note = await addSocAlertNote(selectedAlert.id, {
        author: 'SOC Analyst',
        note: newNoteText.trim()
      });
      const updated = { ...selectedAlert, notes: [...(selectedAlert.notes || []), note] };
      setSelectedAlert(updated);
      setAlerts(alerts.map(a => a.id === selectedAlert.id ? updated : a));
      setNewNoteText('');
    } catch (err) {
      alert('Failed to add note: ' + err.message);
    }
  };

  const handleCreateManualAlert = async (e) => {
    e.preventDefault();
    try {
      const created = await createSocAlert(ingestForm);
      setAlerts([created, ...alerts]);
      setActiveTab('alerts');
      setSelectedAlert(created);
    } catch (err) {
      alert('Failed to ingest alert: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleCreateIncident = async (e) => {
    e.preventDefault();
    try {
      const payload = {
        ...incidentForm,
        alert_ids: selectedAlert ? [selectedAlert.id] : []
      };
      const created = await createSocIncident(payload);
      setIncidents([created, ...incidents]);
      setIsNewIncidentOpen(false);
      setActiveTab('incidents');
      setSelectedIncident(created);
      loadData();
    } catch (err) {
      alert('Failed to create incident: ' + (err.response?.data?.detail || err.message));
    }
  };

  const openAiForAlert = (alertItem) => {
    setAiEvidence(alertItem);
    setIsAiOpen(true);
  };

  const getSeverityBadge = (sev) => {
    const s = sev?.toLowerCase();
    if (s === 'critical') return 'bg-rose-500/20 text-rose-300 border-rose-500/30';
    if (s === 'high') return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
    if (s === 'medium') return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
    return 'bg-teal-500/20 text-teal-300 border-teal-500/30';
  };

  return (
    <div className="min-h-screen p-4 md:p-8 relative bg-[#090A0F] text-slate-100 flex flex-col justify-between">
      {/* Background cyber gradients */}
      <div className="absolute top-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-rose-500/5 blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-indigo-500/10 blur-[120px] pointer-events-none"></div>

      <div className="max-w-7xl w-full mx-auto z-10 flex-1">
        <Navbar
          activeWorkspaceTitle="SOC Analyst Workspace"
          onOpenAi={() => { setAiEvidence(selectedAlert || alerts[0] || null); setIsAiOpen(true); }}
          onOpenIntegrations={() => setIsIntegrationsOpen(true)}
        />

        {/* Top Header Banner */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs font-semibold uppercase tracking-wider mb-2">
              🚨 Security Operations Center
            </div>
            <h1 className="text-3xl md:text-4xl font-black bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-100 to-rose-400">
              SOC Analyst Workspace
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Real alert triage, SIEM telemetry investigation, incident response, and analyst audit tracking.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsNewIncidentOpen(true)}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-rose-500 hover:bg-rose-400 text-[#090A0F] shadow-lg shadow-rose-500/20 transition cursor-pointer flex items-center gap-1.5"
            >
              <span>+</span>
              <span>Create Incident</span>
            </button>
            <button
              onClick={handleSyncWazuh}
              disabled={syncLoading}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-white/10 hover:bg-white/15 text-slate-200 border border-white/10 transition cursor-pointer flex items-center gap-1.5"
            >
              <span>{syncLoading ? '⏳' : '🔄'}</span>
              <span>Sync Wazuh SIEM</span>
            </button>
          </div>
        </div>

        {/* Wazuh Integration Health Banner */}
        <div className="mb-6 p-4 rounded-2xl cyber-glass border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-xl">
              🛡️
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-400">SIEM Telemetry:</span>
                <span className="text-sm font-semibold text-white">Wazuh Manager</span>
                {wazuhStatus?.connected ? (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-teal-500/10 text-teal-300 border border-teal-500/20 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse"></span>
                    Connected ({wazuhStatus.version || 'API OK'})
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-amber-500/10 text-amber-300 border border-amber-500/20">
                    Not Configured / Reachable
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {wazuhStatus?.message || 'Inspecting Wazuh credentials...'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {syncMessage && (
              <span className="text-xs text-teal-300 font-mono bg-teal-500/10 px-2 py-1 rounded">
                {syncMessage}
              </span>
            )}
            <button
              onClick={() => setIsIntegrationsOpen(true)}
              className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition"
            >
              Integration Settings &rarr;
            </button>
          </div>
        </div>

        {/* Metric Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="p-4 rounded-xl cyber-glass border border-white/5">
            <span className="text-[11px] font-bold uppercase text-slate-400 tracking-wider">Total Alerts</span>
            <div className="text-2xl font-black text-white mt-1">{alerts.length}</div>
            <span className="text-[10px] text-slate-500 font-mono">Real ingested telemetry</span>
          </div>

          <div className="p-4 rounded-xl cyber-glass border border-white/5">
            <span className="text-[11px] font-bold uppercase text-amber-400 tracking-wider">In Triage / New</span>
            <div className="text-2xl font-black text-amber-300 mt-1">
              {alerts.filter(a => a.status === 'new' || a.status === 'in_triage').length}
            </div>
            <span className="text-[10px] text-slate-500 font-mono">Awaiting investigation</span>
          </div>

          <div className="p-4 rounded-xl cyber-glass border border-white/5">
            <span className="text-[11px] font-bold uppercase text-rose-400 tracking-wider">High & Critical</span>
            <div className="text-2xl font-black text-rose-300 mt-1">
              {alerts.filter(a => a.severity === 'high' || a.severity === 'critical').length}
            </div>
            <span className="text-[10px] text-slate-500 font-mono">Priority response</span>
          </div>

          <div className="p-4 rounded-xl cyber-glass border border-white/5">
            <span className="text-[11px] font-bold uppercase text-indigo-400 tracking-wider">Active Incidents</span>
            <div className="text-2xl font-black text-indigo-300 mt-1">
              {incidents.filter(i => i.status !== 'closed' && i.status !== 'resolved').length}
            </div>
            <span className="text-[10px] text-slate-500 font-mono">Open incident cases</span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 border-b border-white/10 mb-6 pb-2">
          <button
            onClick={() => setActiveTab('alerts')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
              activeTab === 'alerts'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                : 'text-slate-400 hover:text-white hover:bg-white/5'
            }`}
          >
            🚨 Alerts Feed ({alerts.length})
          </button>
          <button
            onClick={() => setActiveTab('incidents')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
              activeTab === 'incidents'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                : 'text-slate-400 hover:text-white hover:bg-white/5'
            }`}
          >
            📁 Incident Cases ({incidents.length})
          </button>
          <button
            onClick={() => setActiveTab('ingest')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
              activeTab === 'ingest'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                : 'text-slate-400 hover:text-white hover:bg-white/5'
            }`}
          >
            ➕ Ingest Telemetry
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
              activeTab === 'audit'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                : 'text-slate-400 hover:text-white hover:bg-white/5'
            }`}
          >
            📜 Analyst Audit Trail
          </button>
        </div>

        {/* TAB 1: ALERTS FEED */}
        {activeTab === 'alerts' && (
          <div className="space-y-4">
            {/* Filter Bar */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <input
                type="text"
                placeholder="Search rule ID, host IP, or description..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="px-3.5 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-rose-400"
              />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-3.5 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-slate-300 focus:outline-none focus:border-rose-400"
              >
                <option value="" className="bg-[#0e1017]">All Severities</option>
                <option value="critical" className="bg-[#0e1017]">Critical</option>
                <option value="high" className="bg-[#0e1017]">High</option>
                <option value="medium" className="bg-[#0e1017]">Medium</option>
                <option value="low" className="bg-[#0e1017]">Low</option>
              </select>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-3.5 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-slate-300 focus:outline-none focus:border-rose-400"
              >
                <option value="" className="bg-[#0e1017]">All Statuses</option>
                <option value="new" className="bg-[#0e1017]">New</option>
                <option value="in_triage" className="bg-[#0e1017]">In Triage</option>
                <option value="investigating" className="bg-[#0e1017]">Investigating</option>
                <option value="contained" className="bg-[#0e1017]">Contained</option>
                <option value="closed" className="bg-[#0e1017]">Closed</option>
                <option value="false_positive" className="bg-[#0e1017]">False Positive</option>
              </select>
            </div>

            {/* Alerts Table / List */}
            {loading ? (
              <div className="py-16 text-center text-slate-400 text-sm">Loading security alerts...</div>
            ) : alerts.length === 0 ? (
              <div className="py-16 text-center cyber-glass rounded-2xl border border-white/5 p-8">
                <span className="text-3xl block mb-2">🔕</span>
                <h4 className="font-bold text-slate-300">No Security Alerts Ingested</h4>
                <p className="text-xs text-slate-500 max-w-md mx-auto mt-1 mb-4">
                  Cyber Monkey never fabricates fake alerts. Connect Wazuh SIEM or use the <em>Ingest Telemetry</em> tab to import real security events.
                </p>
                <button
                  onClick={() => setActiveTab('ingest')}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30 hover:bg-rose-500/30 transition cursor-pointer"
                >
                  Ingest First Alert &rarr;
                </button>
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Alert Cards Column */}
                <div className="lg:col-span-2 space-y-3">
                  {alerts.map((alertItem) => {
                    const isSelected = selectedAlert?.id === alertItem.id;
                    return (
                      <div
                        key={alertItem.id}
                        onClick={() => setSelectedAlert(alertItem)}
                        className={`p-4 rounded-xl border transition cursor-pointer relative overflow-hidden ${
                          isSelected
                            ? 'bg-white/[0.06] border-rose-500/40 shadow-lg shadow-rose-500/5'
                            : 'bg-white/[0.02] border-white/5 hover:border-white/10 hover:bg-white/[0.04]'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-3 mb-1.5">
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadge(alertItem.severity)}`}>
                              {alertItem.severity}
                            </span>
                            <span className="font-mono text-xs text-slate-400">Rule {alertItem.rule_id}</span>
                            <span className="text-[10px] text-slate-500">via {alertItem.source}</span>
                          </div>
                          <span className="text-[10px] font-mono text-slate-500">
                            {new Date(alertItem.timestamp).toLocaleString()}
                          </span>
                        </div>

                        <h4 className="font-semibold text-sm text-slate-200 line-clamp-2 mb-2">
                          {alertItem.rule_description}
                        </h4>

                        <div className="flex items-center justify-between text-xs text-slate-400">
                          <span className="font-mono text-[11px] bg-white/5 px-2 py-0.5 rounded">
                            Host: {alertItem.host_name || alertItem.host_ip || 'Unknown'}
                          </span>
                          <span className="uppercase text-[10px] font-bold text-slate-400">
                            Status: <strong className="text-slate-200">{alertItem.status}</strong>
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Selected Alert Details Column */}
                <div className="cyber-glass rounded-2xl border border-white/10 p-5 h-fit sticky top-6">
                  {selectedAlert ? (
                    <div className="space-y-4">
                      <div className="flex items-start justify-between pb-3 border-b border-white/10">
                        <div>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadge(selectedAlert.severity)}`}>
                            {selectedAlert.severity}
                          </span>
                          <h3 className="font-bold text-base text-white mt-2">
                            {selectedAlert.rule_description}
                          </h3>
                        </div>
                        <button
                          onClick={() => openAiForAlert(selectedAlert)}
                          className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-teal-400 to-indigo-500 text-[#090A0F] shadow cursor-pointer flex items-center gap-1"
                        >
                          <span>🧠</span>
                          <span>AI Triage</span>
                        </button>
                      </div>

                      {/* Metadata */}
                      <div className="space-y-2 text-xs">
                        <div className="flex justify-between py-1 border-b border-white/5">
                          <span className="text-slate-400">Alert ID:</span>
                          <span className="font-mono text-slate-200">{selectedAlert.alert_id}</span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-white/5">
                          <span className="text-slate-400">Rule Level:</span>
                          <span className="font-mono text-slate-200">{selectedAlert.rule_level} / 15</span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-white/5">
                          <span className="text-slate-400">Host IP / Name:</span>
                          <span className="font-mono text-slate-200">{selectedAlert.host_ip || selectedAlert.host_name || 'N/A'}</span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-white/5">
                          <span className="text-slate-400">Detection Source:</span>
                          <span className="text-slate-200">{selectedAlert.source}</span>
                        </div>
                      </div>

                      {/* Evidence raw text */}
                      {selectedAlert.evidence && (
                        <div>
                          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                            Evidence Log:
                          </label>
                          <pre className="p-2.5 rounded-xl bg-black/40 border border-white/5 font-mono text-[11px] text-teal-300 whitespace-pre-wrap max-h-32 overflow-y-auto">
                            {selectedAlert.evidence}
                          </pre>
                        </div>
                      )}

                      {/* Triage Status Selector */}
                      <div>
                        <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                          Triage Workflow Status:
                        </label>
                        <select
                          value={selectedAlert.status}
                          onChange={(e) => handleUpdateAlertStatus(selectedAlert.id, e.target.value)}
                          className="w-full px-3 py-1.5 bg-white/5 border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-rose-400"
                        >
                          <option value="new" className="bg-[#0e1017]">New</option>
                          <option value="in_triage" className="bg-[#0e1017]">In Triage</option>
                          <option value="investigating" className="bg-[#0e1017]">Investigating</option>
                          <option value="contained" className="bg-[#0e1017]">Contained</option>
                          <option value="closed" className="bg-[#0e1017]">Closed</option>
                          <option value="false_positive" className="bg-[#0e1017]">False Positive</option>
                        </select>
                      </div>

                      {/* Notes Thread */}
                      <div className="pt-2 border-t border-white/10">
                        <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-2">
                          Analyst Investigation Notes ({selectedAlert.notes?.length || 0}):
                        </label>
                        <div className="space-y-2 max-h-36 overflow-y-auto pr-1 mb-2">
                          {selectedAlert.notes?.map((n) => (
                            <div key={n.id} className="p-2 rounded-lg bg-white/[0.02] border border-white/5 text-xs">
                              <div className="flex justify-between text-[10px] text-slate-400 mb-0.5">
                                <strong>{n.author}</strong>
                                <span>{new Date(n.created_at).toLocaleTimeString()}</span>
                              </div>
                              <p className="text-slate-300">{n.note}</p>
                            </div>
                          ))}
                        </div>

                        <div className="flex gap-2">
                          <input
                            type="text"
                            placeholder="Add note..."
                            value={newNoteText}
                            onChange={(e) => setNewNoteText(e.target.value)}
                            className="flex-1 px-3 py-1.5 bg-white/5 border border-white/10 rounded-lg text-xs text-white focus:outline-none"
                          />
                          <button
                            onClick={handleAddAlertNote}
                            className="px-3 py-1.5 rounded-lg text-xs bg-white/10 hover:bg-white/20 text-white font-medium cursor-pointer"
                          >
                            Add
                          </button>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="py-12 text-center text-slate-500 text-xs">
                      Select an alert from the feed to view raw telemetry, triage, and analyst notes.
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: INCIDENTS TRACKER */}
        {activeTab === 'incidents' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-bold text-lg text-white">Security Incidents & Escalations</h3>
              <button
                onClick={() => setIsNewIncidentOpen(true)}
                className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-rose-500 hover:bg-rose-400 text-[#090A0F] cursor-pointer"
              >
                + Track New Incident
              </button>
            </div>

            {incidents.length === 0 ? (
              <div className="py-16 text-center cyber-glass rounded-2xl border border-white/5 p-8">
                <span className="text-3xl block mb-2">📁</span>
                <h4 className="font-bold text-slate-300">No Incidents Escalated</h4>
                <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1 mb-4">
                  Incidents track verified security breaches, correlated attack campaigns, and remediation steps.
                </p>
                <button
                  onClick={() => setIsNewIncidentOpen(true)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30 cursor-pointer"
                >
                  Create Incident
                </button>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {incidents.map((inc) => (
                  <div key={inc.id} className="p-5 rounded-2xl cyber-glass border border-white/10 space-y-3">
                    <div className="flex items-start justify-between">
                      <div>
                        <span className="font-mono text-xs text-rose-400 font-bold">{inc.incident_number}</span>
                        <h4 className="text-base font-bold text-white mt-0.5">{inc.title}</h4>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadge(inc.severity)}`}>
                        {inc.severity}
                      </span>
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed">
                      {inc.description || 'No description recorded.'}
                    </p>

                    <div className="flex items-center justify-between text-xs pt-3 border-t border-white/5">
                      <span className="text-slate-400">Assigned: <strong className="text-slate-200">{inc.assigned_to || 'Unassigned'}</strong></span>
                      <span className="uppercase font-mono text-[10px] font-bold text-slate-300 bg-white/5 px-2 py-0.5 rounded">
                        Status: {inc.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TAB 3: INGEST TELEMETRY */}
        {activeTab === 'ingest' && (
          <div className="max-w-2xl mx-auto cyber-glass rounded-2xl border border-white/10 p-6 md:p-8">
            <h3 className="font-bold text-lg text-white mb-1">Manual Alert / Telemetry Ingestion</h3>
            <p className="text-xs text-slate-400 mb-6">
              Ingest verified security telemetry into the SOC pipeline for investigation and triage.
            </p>

            <form onSubmit={handleCreateManualAlert} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Rule ID</label>
                  <input
                    type="text"
                    required
                    value={ingestForm.rule_id}
                    onChange={(e) => setIngestForm({ ...ingestForm, rule_id: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-rose-400"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Severity</label>
                  <select
                    value={ingestForm.severity}
                    onChange={(e) => setIngestForm({ ...ingestForm, severity: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-rose-400"
                  >
                    <option value="critical" className="bg-[#0e1017]">Critical</option>
                    <option value="high" className="bg-[#0e1017]">High</option>
                    <option value="medium" className="bg-[#0e1017]">Medium</option>
                    <option value="low" className="bg-[#0e1017]">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Rule Description</label>
                <input
                  type="text"
                  required
                  value={ingestForm.rule_description}
                  onChange={(e) => setIngestForm({ ...ingestForm, rule_description: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-rose-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Host Name</label>
                  <input
                    type="text"
                    value={ingestForm.host_name}
                    onChange={(e) => setIngestForm({ ...ingestForm, host_name: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-rose-400"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Host IP</label>
                  <input
                    type="text"
                    value={ingestForm.host_ip}
                    onChange={(e) => setIngestForm({ ...ingestForm, host_ip: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-rose-400"
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Raw Evidence Log</label>
                <textarea
                  rows={3}
                  value={ingestForm.evidence}
                  onChange={(e) => setIngestForm({ ...ingestForm, evidence: e.target.value })}
                  className="w-full font-mono text-xs px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-teal-300 focus:outline-none focus:border-rose-400"
                />
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="submit"
                  className="px-5 py-2.5 rounded-xl text-xs font-semibold bg-rose-500 hover:bg-rose-400 text-[#090A0F] shadow-lg shadow-rose-500/20 transition cursor-pointer"
                >
                  Ingest Alert into SOC Feed
                </button>
              </div>
            </form>
          </div>
        )}

        {/* TAB 4: AUDIT TRAIL */}
        {activeTab === 'audit' && (
          <div className="cyber-glass rounded-2xl border border-white/10 p-6">
            <h3 className="font-bold text-lg text-white mb-4">Analyst Activity & Compliance Audit Log</h3>
            {auditLogs.length === 0 ? (
              <p className="text-xs text-slate-500">No activity logged yet.</p>
            ) : (
              <div className="space-y-2">
                {auditLogs.map((log) => (
                  <div key={log.id} className="p-3 rounded-xl bg-white/[0.02] border border-white/5 flex items-center justify-between text-xs">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-[10px] bg-rose-500/10 text-rose-300 px-2 py-0.5 rounded border border-rose-500/20">
                        {log.action}
                      </span>
                      <span className="text-slate-200">
                        Target {log.target_type}: <strong className="font-mono">{log.target_id}</strong>
                      </span>
                    </div>
                    <div className="text-right text-[11px] text-slate-400">
                      <span>by {log.performed_by} • </span>
                      <span>{new Date(log.created_at).toLocaleString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

      </div>

      {/* CREATE INCIDENT MODAL */}
      {isNewIncidentOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-[#0e1017] border border-white/10 rounded-2xl p-6 relative">
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
              <h3 className="font-bold text-base text-white">Track New Security Incident</h3>
              <button
                onClick={() => setIsNewIncidentOpen(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateIncident} className="space-y-4">
              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Incident Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Unauthorized Privilege Escalation on WS-04"
                  value={incidentForm.title}
                  onChange={(e) => setIncidentForm({ ...incidentForm, title: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-rose-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Severity</label>
                  <select
                    value={incidentForm.severity}
                    onChange={(e) => setIncidentForm({ ...incidentForm, severity: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  >
                    <option value="critical" className="bg-[#0e1017]">Critical</option>
                    <option value="high" className="bg-[#0e1017]">High</option>
                    <option value="medium" className="bg-[#0e1017]">Medium</option>
                    <option value="low" className="bg-[#0e1017]">Low</option>
                  </select>
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Assigned Analyst</label>
                  <input
                    type="text"
                    value={incidentForm.assigned_to}
                    onChange={(e) => setIncidentForm({ ...incidentForm, assigned_to: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Description</label>
                <textarea
                  rows={3}
                  value={incidentForm.description}
                  onChange={(e) => setIncidentForm({ ...incidentForm, description: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsNewIncidentOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs bg-white/10 hover:bg-white/15 text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-rose-500 hover:bg-rose-400 text-[#090A0F]"
                >
                  Create Incident
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* SHARED AI CYBER ASSISTANT MODAL */}
      <AiCyberAssistantModal
        isOpen={isAiOpen}
        onClose={() => setIsAiOpen(false)}
        initialWorkspace="soc"
        initialEvidence={aiEvidence}
        initialTask="explain"
      />

      {/* CENTRAL INTEGRATIONS HEALTH MODAL */}
      <IntegrationsModal
        isOpen={isIntegrationsOpen}
        onClose={() => setIsIntegrationsOpen(false)}
      />
    </div>
  );
};

export default SocWorkspace;
