import React, { useState, useEffect } from 'react';
import {
  getForensicsStatus,
  getForensicCases,
  createForensicCase,
  getForensicCase,
  acquireEvidence,
  verifyEvidenceIntegrity,
  addChainOfCustody,
  addForensicTimelineEvent,
  addForensicNote,
  exportForensicCaseJson,
  exportForensicTimelineCsv
} from '../services/api';
import Navbar from '../components/Navbar';
import AiCyberAssistantModal from '../components/AiCyberAssistantModal';
import IntegrationsModal from '../components/IntegrationsModal';

const ForensicsWorkspace = () => {
  const [engineStatus, setEngineStatus] = useState(null);
  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [loading, setLoading] = useState(true);
  const [verifyingId, setVerifyingId] = useState(null);

  // Active view tab: 'evidence' | 'custody' | 'timeline' | 'notes'
  const [activeTab, setActiveTab] = useState('evidence');

  // Modals
  const [isNewCaseOpen, setIsNewCaseOpen] = useState(false);
  const [isAcquireOpen, setIsAcquireOpen] = useState(false);
  const [isAddTimelineOpen, setIsAddTimelineOpen] = useState(false);
  const [isCustodyOpen, setIsCustodyOpen] = useState(false);
  const [isAiOpen, setIsAiOpen] = useState(false);
  const [isIntegrationsOpen, setIsIntegrationsOpen] = useState(false);

  // Forms
  const [caseForm, setCaseForm] = useState({
    case_number: `DFIR-${new Date().getFullYear()}-001`,
    title: '',
    description: '',
    investigator: 'Lead Forensic Investigator',
    priority: 'high'
  });

  const [acquireForm, setAcquireForm] = useState({
    evidence_identifier: 'ITEM-001',
    media_type: 'log_file',
    source_location: '',
    collector_name: 'Lead Forensic Investigator',
    notes: ''
  });
  const [acquireFile, setAcquireFile] = useState(null);

  const [timelineForm, setTimelineForm] = useState({
    timestamp: new Date().toISOString().slice(0, 16),
    event_source: 'Authentication Log',
    source_host: '',
    user_account: '',
    event_description: '',
    severity: 'info'
  });

  const [custodyForm, setCustodyForm] = useState({
    action: 'CUSTODY_TRANSFER',
    performed_by: 'Lead Forensic Investigator',
    location: 'Evidence Safe Locker A',
    reason: 'Secure evidence preservation and chain of custody log.'
  });
  const [selectedEvidenceForCustody, setSelectedEvidenceForCustody] = useState(null);

  const [newNoteText, setNewNoteText] = useState('');

  const loadData = async () => {
    setLoading(true);
    try {
      const [status, caseList] = await Promise.all([
        getForensicsStatus().catch(() => ({})),
        getForensicCases()
      ]);
      setEngineStatus(status);
      setCases(caseList);
      if (caseList.length > 0) {
        loadCaseDetail(caseList[0].id);
      }
    } catch (err) {
      console.error('Error loading forensics data:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadCaseDetail = async (caseId) => {
    try {
      const detail = await getForensicCase(caseId);
      setSelectedCase(detail);
    } catch (err) {
      alert('Failed to load case detail: ' + err.message);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCreateCase = async (e) => {
    e.preventDefault();
    try {
      const created = await createForensicCase(caseForm);
      setCases([created, ...cases]);
      setSelectedCase(created);
      setIsNewCaseOpen(false);
      setCaseForm({
        case_number: `DFIR-${new Date().getFullYear()}-${String(cases.length + 2).padStart(3, '0')}`,
        title: '',
        description: '',
        investigator: 'Lead Forensic Investigator',
        priority: 'high'
      });
    } catch (err) {
      alert('Failed to create case: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleAcquireEvidence = async (e) => {
    e.preventDefault();
    if (!acquireFile || !selectedCase) return;

    const formData = new FormData();
    formData.append('file', acquireFile);
    formData.append('evidence_identifier', acquireForm.evidence_identifier);
    formData.append('media_type', acquireForm.media_type);
    formData.append('source_location', acquireForm.source_location);
    formData.append('collector_name', acquireForm.collector_name);
    if (acquireForm.notes) formData.append('notes', acquireForm.notes);

    try {
      await acquireEvidence(selectedCase.id, formData);
      setIsAcquireOpen(false);
      setAcquireFile(null);
      loadCaseDetail(selectedCase.id);
    } catch (err) {
      alert('Failed to acquire evidence: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleVerifyIntegrity = async (evidenceId) => {
    setVerifyingId(evidenceId);
    try {
      const res = await verifyEvidenceIntegrity(evidenceId);
      alert(res.message);
      if (selectedCase) {
        loadCaseDetail(selectedCase.id);
      }
    } catch (err) {
      alert('Integrity verification failed: ' + (err.response?.data?.detail || err.message));
    } finally {
      setVerifyingId(null);
    }
  };

  const handleAddCustody = async (e) => {
    e.preventDefault();
    if (!selectedEvidenceForCustody) return;
    try {
      await addChainOfCustody(selectedEvidenceForCustody.id, custodyForm);
      setIsCustodyOpen(false);
      loadCaseDetail(selectedCase.id);
    } catch (err) {
      alert('Failed to log chain of custody: ' + err.message);
    }
  };

  const handleAddTimeline = async (e) => {
    e.preventDefault();
    if (!selectedCase) return;
    try {
      await addForensicTimelineEvent(selectedCase.id, {
        ...timelineForm,
        timestamp: new Date(timelineForm.timestamp).toISOString()
      });
      setIsAddTimelineOpen(false);
      loadCaseDetail(selectedCase.id);
    } catch (err) {
      alert('Failed to add timeline event: ' + err.message);
    }
  };

  const handleAddNote = async () => {
    if (!newNoteText.trim() || !selectedCase) return;
    try {
      const note = await addForensicNote(selectedCase.id, {
        author: 'Forensic Investigator',
        content: newNoteText.trim()
      });
      setSelectedCase({
        ...selectedCase,
        notes: [...(selectedCase.notes || []), note]
      });
      setNewNoteText('');
    } catch (err) {
      alert('Failed to add note: ' + err.message);
    }
  };

  const handleExportJson = async () => {
    if (!selectedCase) return;
    try {
      const res = await exportForensicCaseJson(selectedCase.id);
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(res, null, 2));
      const a = document.createElement('a');
      a.setAttribute("href", dataStr);
      a.setAttribute("download", `${selectedCase.case_number}_full_case_export.json`);
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err) {
      alert('Failed to export JSON: ' + err.message);
    }
  };

  const handleExportCsv = async () => {
    if (!selectedCase) return;
    try {
      const blob = await exportForensicTimelineCsv(selectedCase.id);
      const url = window.URL.createObjectURL(new Blob([blob]));
      const a = document.createElement('a');
      a.href = url;
      a.setAttribute('download', `${selectedCase.case_number}_timeline.csv`);
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err) {
      alert('Failed to export CSV: ' + err.message);
    }
  };

  // Combine all chain of custody entries across evidence
  const allCustodyRecords = selectedCase?.evidence?.flatMap(ev =>
    (ev.chain_of_custody || []).map(c => ({ ...c, evidence_identifier: ev.evidence_identifier, filename: ev.original_filename }))
  ) || [];

  return (
    <div className="min-h-screen p-4 md:p-8 relative bg-[#090A0F] text-slate-100 flex flex-col justify-between">
      {/* Background cyber glow */}
      <div className="absolute top-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-violet-500/5 blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-indigo-500/10 blur-[120px] pointer-events-none"></div>

      <div className="max-w-7xl w-full mx-auto z-10 flex-1">
        <Navbar
          activeWorkspaceTitle="Digital Forensics Workspace"
          onOpenAi={() => setIsAiOpen(true)}
          onOpenIntegrations={() => setIsIntegrationsOpen(true)}
        />

        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-violet-500/10 border border-violet-500/20 text-violet-300 text-xs font-semibold uppercase tracking-wider mb-2">
              🔬 DFIR Evidence & Integrity
            </div>
            <h1 className="text-3xl md:text-4xl font-black bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-100 to-violet-400">
              Digital Forensics Workspace
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Cryptographic SHA-256 evidence preservation, chain of custody verification, and artifact timeline reconstruction.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsNewCaseOpen(true)}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-violet-500 hover:bg-violet-400 text-white shadow-lg shadow-violet-500/20 transition cursor-pointer flex items-center gap-1.5"
            >
              <span>+</span>
              <span>New Case</span>
            </button>
          </div>
        </div>

        {/* Engine Status Banner */}
        <div className="p-4 rounded-2xl cyber-glass border border-violet-500/20 mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-3">
            <span className="text-2xl">⚖️</span>
            <div>
              <div className="font-bold text-slate-200">
                NIST FIPS 180-4 Cryptographic Integrity Verification
              </div>
              <p className="text-slate-400 text-[11px]">
                {engineStatus?.disk_parsing || 'Metadata and cryptographic integrity triage active.'}
              </p>
            </div>
          </div>
          <span className="px-2.5 py-1 rounded-full text-[10px] font-mono bg-violet-500/10 text-violet-300 border border-violet-500/20">
            Storage: Read-Only Isolated
          </span>
        </div>

        {/* Main Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Left Column: Cases List */}
          <div className="cyber-glass rounded-2xl border border-white/10 p-4 space-y-3 h-fit">
            <div className="flex items-center justify-between pb-2 border-b border-white/10">
              <h3 className="font-bold text-sm text-white">Forensic Cases ({cases.length})</h3>
              <button
                onClick={() => setIsNewCaseOpen(true)}
                className="text-violet-400 hover:text-violet-300 text-xs font-semibold cursor-pointer"
              >
                + New
              </button>
            </div>

            {cases.length === 0 ? (
              <div className="py-8 text-center text-slate-500 text-xs">
                No cases created yet.
              </div>
            ) : (
              <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                {cases.map((c) => {
                  const isSelected = selectedCase?.id === c.id;
                  return (
                    <div
                      key={c.id}
                      onClick={() => loadCaseDetail(c.id)}
                      className={`p-3 rounded-xl border transition cursor-pointer ${
                        isSelected
                          ? 'bg-violet-500/10 border-violet-500/30 text-white'
                          : 'bg-white/[0.02] border-white/5 text-slate-300 hover:bg-white/5'
                      }`}
                    >
                      <div className="flex justify-between items-center text-[10px] text-violet-300 font-mono mb-1">
                        <span>{c.case_number}</span>
                        <span className="capitalize">{c.priority}</span>
                      </div>
                      <h4 className="font-semibold text-xs line-clamp-1">{c.title}</h4>
                      <div className="text-[10px] text-slate-400 mt-1">
                        {c.evidence_count || 0} evidence items
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Right Column: Case Details & Workflows */}
          <div className="lg:col-span-3 space-y-6">
            {selectedCase ? (
              <>
                {/* Case Header Card */}
                <div className="cyber-glass rounded-2xl border border-white/10 p-6 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-violet-400 bg-violet-500/10 px-2 py-0.5 rounded border border-violet-500/20">
                          {selectedCase.case_number}
                        </span>
                        <h2 className="text-xl font-bold text-white">{selectedCase.title}</h2>
                      </div>
                      <p className="text-xs text-slate-400 mt-1">
                        Investigator: <strong className="text-slate-200">{selectedCase.investigator}</strong> • Status: <strong className="uppercase text-slate-200">{selectedCase.status}</strong>
                      </p>
                      {selectedCase.description && (
                        <p className="text-xs text-slate-400 mt-2 italic">{selectedCase.description}</p>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setIsAcquireOpen(true)}
                        className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-violet-500 hover:bg-violet-400 text-white shadow cursor-pointer flex items-center gap-1.5"
                      >
                        <span>📥</span>
                        <span>Acquire Evidence</span>
                      </button>
                      <button
                        onClick={() => setIsAiOpen(true)}
                        className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-teal-400 to-indigo-500 text-[#090A0F] shadow cursor-pointer flex items-center gap-1.5"
                      >
                        <span>🧠</span>
                        <span>AI Timeline Synthesis</span>
                      </button>
                      <button
                        onClick={handleExportJson}
                        className="px-3 py-2 rounded-xl text-xs font-semibold bg-white/10 hover:bg-white/15 text-white transition cursor-pointer"
                        title="Export Complete Case JSON"
                      >
                        Export Case
                      </button>
                    </div>
                  </div>

                  {/* Tabs bar */}
                  <div className="flex items-center gap-2 pt-4 border-t border-white/10">
                    <button
                      onClick={() => setActiveTab('evidence')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                        activeTab === 'evidence'
                          ? 'bg-violet-500/20 text-violet-300 border border-violet-500/30'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      📦 Evidence Inventory ({selectedCase.evidence?.length || 0})
                    </button>
                    <button
                      onClick={() => setActiveTab('custody')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                        activeTab === 'custody'
                          ? 'bg-violet-500/20 text-violet-300 border border-violet-500/30'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      📜 Chain of Custody ({allCustodyRecords.length})
                    </button>
                    <button
                      onClick={() => setActiveTab('timeline')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                        activeTab === 'timeline'
                          ? 'bg-violet-500/20 text-violet-300 border border-violet-500/30'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      ⏱️ Artifact Timeline ({selectedCase.timeline_events?.length || 0})
                    </button>
                    <button
                      onClick={() => setActiveTab('notes')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                        activeTab === 'notes'
                          ? 'bg-violet-500/20 text-violet-300 border border-violet-500/30'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      📝 Notes ({selectedCase.notes?.length || 0})
                    </button>
                  </div>
                </div>

                {/* TAB 1: EVIDENCE INVENTORY */}
                {activeTab === 'evidence' && (
                  <div className="space-y-4">
                    {selectedCase.evidence?.length === 0 ? (
                      <div className="py-12 text-center cyber-glass rounded-2xl border border-white/5 p-6">
                        <span className="text-3xl block mb-2">📦</span>
                        <p className="text-xs text-slate-400">
                          No digital evidence items acquired for this case.
                        </p>
                        <button
                          onClick={() => setIsAcquireOpen(true)}
                          className="mt-3 px-4 py-2 rounded-xl text-xs font-semibold bg-violet-500/20 text-violet-300 border border-violet-500/30 cursor-pointer"
                        >
                          Acquire First Item
                        </button>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {selectedCase.evidence.map((ev) => (
                          <div key={ev.id} className="p-4 rounded-xl cyber-glass border border-white/10 space-y-3">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-xs font-bold text-violet-400 bg-white/5 px-2 py-0.5 rounded">
                                  {ev.evidence_identifier}
                                </span>
                                <h4 className="font-bold text-sm text-white">{ev.original_filename}</h4>
                                <span className="text-[10px] uppercase font-mono text-slate-400 bg-white/5 px-1.5 py-0.5 rounded">
                                  {ev.media_type}
                                </span>
                              </div>

                              <div className="flex items-center gap-2">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                  ev.verification_status === 'VERIFIED'
                                    ? 'bg-teal-500/10 text-teal-300 border border-teal-500/20'
                                    : 'bg-rose-500/10 text-rose-300 border border-rose-500/20'
                                }`}>
                                  {ev.verification_status}
                                </span>
                                <button
                                  onClick={() => handleVerifyIntegrity(ev.id)}
                                  disabled={verifyingId === ev.id}
                                  className="px-2.5 py-1 text-xs rounded-lg bg-teal-500/20 hover:bg-teal-500/30 text-teal-300 border border-teal-500/30 font-semibold transition cursor-pointer"
                                >
                                  {verifyingId === ev.id ? 'Re-hashing...' : 'Verify Hash'}
                                </button>
                                <button
                                  onClick={() => {
                                    setSelectedEvidenceForCustody(ev);
                                    setIsCustodyOpen(true);
                                  }}
                                  className="px-2.5 py-1 text-xs rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 cursor-pointer"
                                >
                                  + Custody Transfer
                                </button>
                              </div>
                            </div>

                            {/* Hash and Location */}
                            <div className="text-xs font-mono space-y-1 bg-black/40 p-2.5 rounded-lg border border-white/5">
                              <div className="flex items-center gap-2 truncate">
                                <span className="text-slate-400 text-[10px] uppercase w-28 shrink-0">Acquisition SHA-256:</span>
                                <span className="text-emerald-300 select-all truncate">{ev.acquisition_sha256}</span>
                              </div>
                              <div className="flex items-center gap-2 text-slate-400 text-[11px]">
                                <span className="text-[10px] uppercase w-28 shrink-0">Source Location:</span>
                                <span>{ev.source_location} • Collector: {ev.collector_name}</span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* TAB 2: CHAIN OF CUSTODY */}
                {activeTab === 'custody' && (
                  <div className="cyber-glass rounded-2xl border border-white/10 p-5 space-y-4">
                    <h3 className="font-bold text-base text-white">Chain of Custody Verification Log</h3>
                    {allCustodyRecords.length === 0 ? (
                      <p className="text-xs text-slate-500">No chain of custody transactions logged.</p>
                    ) : (
                      <div className="space-y-2">
                        {allCustodyRecords.map((c) => (
                          <div key={c.id} className="p-3 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-[10px] uppercase font-bold text-violet-300 bg-violet-500/10 px-2 py-0.5 rounded border border-violet-500/20">
                                  {c.action}
                                </span>
                                <strong className="text-slate-200 font-mono">{c.evidence_identifier}</strong>
                                <span className="text-slate-400">({c.filename})</span>
                              </div>
                              <p className="text-slate-300 mt-1">{c.reason}</p>
                            </div>
                            <div className="text-right text-[11px] text-slate-400 shrink-0 font-mono">
                              <div>{c.performed_by} • {c.location}</div>
                              <span className="text-[10px] text-slate-500">{new Date(c.timestamp).toLocaleString()}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* TAB 3: TIMELINE */}
                {activeTab === 'timeline' && (
                  <div className="cyber-glass rounded-2xl border border-white/10 p-5 space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="font-bold text-base text-white">Chronological Forensic Timeline</h3>
                      <div className="flex gap-2">
                        <button
                          onClick={() => setIsAddTimelineOpen(true)}
                          className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-violet-500 text-white cursor-pointer"
                        >
                          + Add Event
                        </button>
                        <button
                          onClick={handleExportCsv}
                          className="px-3 py-1.5 rounded-lg text-xs font-medium bg-white/10 hover:bg-white/15 text-white cursor-pointer"
                        >
                          Export CSV
                        </button>
                      </div>
                    </div>

                    {selectedCase.timeline_events?.length === 0 ? (
                      <p className="text-xs text-slate-500 py-8 text-center">No timeline events recorded.</p>
                    ) : (
                      <div className="space-y-3">
                        {selectedCase.timeline_events.map((t) => (
                          <div key={t.id} className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5 flex items-start gap-3">
                            <span className="font-mono text-[11px] text-violet-300 bg-white/5 px-2 py-1 rounded shrink-0">
                              {new Date(t.timestamp).toLocaleString()}
                            </span>
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="font-bold text-xs text-white">{t.event_source}</span>
                                {t.source_host && <span className="text-[10px] text-slate-400 font-mono">[{t.source_host}]</span>}
                                {t.user_account && <span className="text-[10px] text-teal-300 font-mono">user:{t.user_account}</span>}
                              </div>
                              <p className="text-xs text-slate-300">{t.event_description}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* TAB 4: NOTES */}
                {activeTab === 'notes' && (
                  <div className="cyber-glass rounded-2xl border border-white/10 p-5 space-y-3">
                    <h3 className="font-bold text-sm text-white">Case Notes</h3>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {selectedCase.notes?.map((n) => (
                        <div key={n.id} className="p-2.5 rounded-lg bg-white/[0.02] border border-white/5 text-xs">
                          <div className="flex justify-between text-[10px] text-slate-400 mb-0.5">
                            <strong>{n.author}</strong>
                            <span>{new Date(n.created_at).toLocaleString()}</span>
                          </div>
                          <p className="text-slate-200">{n.content}</p>
                        </div>
                      ))}
                    </div>

                    <div className="flex gap-2 pt-2 border-t border-white/5">
                      <input
                        type="text"
                        placeholder="Add investigator note..."
                        value={newNoteText}
                        onChange={(e) => setNewNoteText(e.target.value)}
                        className="flex-1 px-3 py-1.5 bg-white/5 border border-white/10 rounded-lg text-xs text-white focus:outline-none"
                      />
                      <button
                        onClick={handleAddNote}
                        className="px-4 py-1.5 rounded-lg text-xs bg-violet-500 hover:bg-violet-400 text-white font-bold cursor-pointer"
                      >
                        Add
                      </button>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="py-24 text-center cyber-glass rounded-2xl border border-white/5 p-8">
                <span className="text-4xl block mb-2">🔬</span>
                <h4 className="font-bold text-slate-300">Select or Create a Forensic Case</h4>
                <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1 mb-4">
                  Digital forensics cases safeguard evidentiary chain of custody and cryptographic integrity hashes.
                </p>
                <button
                  onClick={() => setIsNewCaseOpen(true)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-violet-500 hover:bg-violet-400 text-white cursor-pointer"
                >
                  Create Case
                </button>
              </div>
            )}
          </div>
        </div>

      </div>

      {/* CREATE CASE MODAL */}
      {isNewCaseOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-[#0e1017] border border-white/10 rounded-2xl p-6 relative">
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
              <h3 className="font-bold text-base text-white">Open New Forensic Case</h3>
              <button
                onClick={() => setIsNewCaseOpen(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Case Number</label>
                  <input
                    type="text"
                    required
                    value={caseForm.case_number}
                    onChange={(e) => setCaseForm({ ...caseForm, case_number: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-violet-400"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Priority</label>
                  <select
                    value={caseForm.priority}
                    onChange={(e) => setCaseForm({ ...caseForm, priority: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  >
                    <option value="critical" className="bg-[#0e1017]">Critical</option>
                    <option value="high" className="bg-[#0e1017]">High</option>
                    <option value="medium" className="bg-[#0e1017]">Medium</option>
                    <option value="low" className="bg-[#0e1017]">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Case Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Unauthorized Persistence & Registry Triage on Host WS-04"
                  value={caseForm.title}
                  onChange={(e) => setCaseForm({ ...caseForm, title: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-violet-400"
                />
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Lead Investigator</label>
                <input
                  type="text"
                  value={caseForm.investigator}
                  onChange={(e) => setCaseForm({ ...caseForm, investigator: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                />
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Scope & Incident Synopsis</label>
                <textarea
                  rows={2}
                  value={caseForm.description}
                  onChange={(e) => setCaseForm({ ...caseForm, description: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsNewCaseOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs bg-white/10 hover:bg-white/15 text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-violet-500 hover:bg-violet-400 text-white"
                >
                  Open Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ACQUIRE EVIDENCE MODAL */}
      {isAcquireOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-[#0e1017] border border-white/10 rounded-2xl p-6 relative">
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
              <h3 className="font-bold text-base text-white">Acquire & Ingest Digital Evidence</h3>
              <button
                onClick={() => setIsAcquireOpen(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleAcquireEvidence} className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Evidence ID</label>
                  <input
                    type="text"
                    required
                    value={acquireForm.evidence_identifier}
                    onChange={(e) => setAcquireForm({ ...acquireForm, evidence_identifier: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Media Type</label>
                  <select
                    value={acquireForm.media_type}
                    onChange={(e) => setAcquireForm({ ...acquireForm, media_type: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  >
                    <option value="log_file" className="bg-[#0e1017]">System / Auth Log</option>
                    <option value="pcap" className="bg-[#0e1017]">Packet Capture (PCAP)</option>
                    <option value="memory_dump" className="bg-[#0e1017]">Memory Dump</option>
                    <option value="filesystem_triage" className="bg-[#0e1017]">Filesystem Triage</option>
                    <option value="disk_image" className="bg-[#0e1017]">Raw Disk Image</option>
                    <option value="document" className="bg-[#0e1017]">Document / Artifact</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Evidence File</label>
                <input
                  type="file"
                  required
                  onChange={(e) => setAcquireFile(e.target.files?.[0] || null)}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-slate-300"
                />
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Source Physical / Logical Location</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Host WS-04, C:\Windows\System32\winevt\Logs\Security.evtx"
                  value={acquireForm.source_location}
                  onChange={(e) => setAcquireForm({ ...acquireForm, source_location: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                />
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Collector Name</label>
                <input
                  type="text"
                  required
                  value={acquireForm.collector_name}
                  onChange={(e) => setAcquireForm({ ...acquireForm, collector_name: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAcquireOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs bg-white/10 hover:bg-white/15 text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-violet-500 hover:bg-violet-400 text-white"
                >
                  Ingest & Compute SHA-256
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ADD TIMELINE EVENT MODAL */}
      {isAddTimelineOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-[#0e1017] border border-white/10 rounded-2xl p-6 relative">
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
              <h3 className="font-bold text-base text-white">Add Timeline Artifact Event</h3>
              <button
                onClick={() => setIsAddTimelineOpen(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleAddTimeline} className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Timestamp</label>
                  <input
                    type="datetime-local"
                    required
                    value={timelineForm.timestamp}
                    onChange={(e) => setTimelineForm({ ...timelineForm, timestamp: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Event Source</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Auth Log, Registry, Prefetch"
                    value={timelineForm.event_source}
                    onChange={(e) => setTimelineForm({ ...timelineForm, event_source: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Source Host</label>
                  <input
                    type="text"
                    value={timelineForm.source_host}
                    onChange={(e) => setTimelineForm({ ...timelineForm, source_host: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">User Account</label>
                  <input
                    type="text"
                    value={timelineForm.user_account}
                    onChange={(e) => setTimelineForm({ ...timelineForm, user_account: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Event Description</label>
                <textarea
                  rows={2}
                  required
                  value={timelineForm.event_description}
                  onChange={(e) => setTimelineForm({ ...timelineForm, event_description: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAddTimelineOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs bg-white/10 hover:bg-white/15 text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-violet-500 hover:bg-violet-400 text-white"
                >
                  Add Event
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* CUSTODY TRANSFER MODAL */}
      {isCustodyOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-[#0e1017] border border-white/10 rounded-2xl p-6 relative">
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
              <h3 className="font-bold text-base text-white">Record Chain of Custody Transfer</h3>
              <button
                onClick={() => setIsCustodyOpen(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleAddCustody} className="space-y-4">
              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Action</label>
                <select
                  value={custodyForm.action}
                  onChange={(e) => setCustodyForm({ ...custodyForm, action: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                >
                  <option value="CUSTODY_TRANSFER" className="bg-[#0e1017]">Custody Transfer</option>
                  <option value="TRIAGE_ANALYSIS" className="bg-[#0e1017]">Triage Analysis Checkout</option>
                  <option value="SECURE_STORAGE" className="bg-[#0e1017]">Secure Storage Return</option>
                </select>
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Performed By</label>
                <input
                  type="text"
                  required
                  value={custodyForm.performed_by}
                  onChange={(e) => setCustodyForm({ ...custodyForm, performed_by: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                />
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Location</label>
                <input
                  type="text"
                  required
                  value={custodyForm.location}
                  onChange={(e) => setCustodyForm({ ...custodyForm, location: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                />
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Reason / Purpose</label>
                <textarea
                  rows={2}
                  required
                  value={custodyForm.reason}
                  onChange={(e) => setCustodyForm({ ...custodyForm, reason: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsCustodyOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs bg-white/10 hover:bg-white/15 text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-violet-500 hover:bg-violet-400 text-white"
                >
                  Log Custody Event
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
        initialWorkspace="forensics"
        initialEvidence={selectedCase ? {
          case_number: selectedCase.case_number,
          investigator: selectedCase.investigator,
          evidence_count: selectedCase.evidence?.length || 0,
          timeline_events_count: selectedCase.timeline_events?.length || 0,
          timeline_sample: selectedCase.timeline_events?.slice(0, 5) || []
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

export default ForensicsWorkspace;
