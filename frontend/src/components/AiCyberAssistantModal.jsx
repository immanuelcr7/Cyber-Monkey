import React, { useState, useEffect } from 'react';
import { getAiStatus, analyzeWithAi } from '../services/api';

const AiCyberAssistantModal = ({
  isOpen,
  onClose,
  initialWorkspace = 'soc',
  initialEvidence = null,
  initialTask = 'explain'
}) => {
  const [statusInfo, setStatusInfo] = useState(null);
  const [workspace, setWorkspace] = useState(initialWorkspace);
  const [taskType, setTaskType] = useState(initialTask);
  const [userQuery, setUserQuery] = useState('');
  const [evidenceJson, setEvidenceJson] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (isOpen) {
      loadStatus();
      if (initialEvidence) {
        setEvidenceJson(JSON.stringify(initialEvidence, null, 2));
      } else {
        setEvidenceJson(JSON.stringify({ note: "Select an alert, sample, or investigation in workspace to provide real evidence." }, null, 2));
      }
      setWorkspace(initialWorkspace);
      setTaskType(initialTask);
      setAnalysisResult(null);
    }
  }, [isOpen, initialEvidence, initialWorkspace, initialTask]);

  const loadStatus = async () => {
    try {
      const res = await getAiStatus();
      setStatusInfo(res);
    } catch {
      setStatusInfo({ configured: false, message: "AI provider offline or backend error." });
    }
  };

  const handleRunAnalysis = async () => {
    setLoading(true);
    setError(null);
    setAnalysisResult(null);

    let parsedEvidence = {};
    try {
      parsedEvidence = JSON.parse(evidenceJson || '{}');
    } catch {
      setError('Evidence context must be valid JSON.');
      setLoading(false);
      return;
    }

    try {
      const result = await analyzeWithAi({
        workspace,
        task_type: taskType,
        evidence: parsedEvidence,
        user_query: userQuery || undefined
      });
      setAnalysisResult(result);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-4xl bg-[#0e1017] border border-white/10 rounded-2xl shadow-2xl p-6 md:p-8 relative max-h-[90vh] flex flex-col">
        {/* Modal Header */}
        <div className="flex items-center justify-between pb-4 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-teal-400 to-indigo-500 flex items-center justify-center text-xl shadow-lg shadow-teal-500/20 font-mono">
              🧠
            </div>
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                Shared AI Cyber Assistant
              </h2>
              <p className="text-xs text-slate-400">
                Grounded cybersecurity explanation, MITRE ATT&CK mapping, and remediation guidance.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white flex items-center justify-center cursor-pointer text-lg font-bold"
          >
            &times;
          </button>
        </div>

        {/* Provider Status Indicator */}
        <div className="my-3 p-3 rounded-xl bg-white/[0.02] border border-white/5 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Engine / Provider:</span>
            <span className="font-semibold text-teal-300">
              {statusInfo?.provider ? statusInfo.provider.toUpperCase() : 'Cyber Monkey Grounded Expert Engine'}
            </span>
            {statusInfo?.model && (
              <span className="text-slate-400">({statusInfo.model})</span>
            )}
          </div>
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
            statusInfo?.configured ? 'bg-teal-500/10 text-teal-300 border border-teal-500/20' : 'bg-indigo-500/10 text-indigo-300 border border-indigo-500/20'
          }`}>
            {statusInfo?.configured ? 'Cloud Generative Active' : 'Local Grounded Active'}
          </span>
        </div>

        {/* Modal Body */}
        <div className="overflow-y-auto py-2 flex-1 space-y-4 pr-1">
          {/* Controls Bar */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">
                Target Workspace
              </label>
              <select
                value={workspace}
                onChange={(e) => setWorkspace(e.target.value)}
                className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-teal-400"
              >
                <option value="soc" className="bg-[#0e1017]">SOC Analyst (Alerts & Incidents)</option>
                <option value="osint" className="bg-[#0e1017]">OSINT (Intelligence & Footprints)</option>
                <option value="malware" className="bg-[#0e1017]">Malware Analysis (Triage & IoCs)</option>
                <option value="forensics" className="bg-[#0e1017]">Digital Forensics (Evidence & Timeline)</option>
                <option value="network" className="bg-[#0e1017]">Network Monitoring (Assets & Telemetry)</option>
                <option value="pentest" className="bg-[#0e1017]">Penetration Testing</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">
                Analysis Task Type
              </label>
              <select
                value={taskType}
                onChange={(e) => setTaskType(e.target.value)}
                className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-teal-400"
              >
                <option value="explain" className="bg-[#0e1017]">Explain Security Finding</option>
                <option value="summarize" className="bg-[#0e1017]">Summarize Evidence</option>
                <option value="recommend" className="bg-[#0e1017]">Remediation & Next Steps</option>
                <option value="triage" className="bg-[#0e1017]">Investigative Triage Assessment</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">
                Analyst Query (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g., What MITRE techniques apply here?"
                value={userQuery}
                onChange={(e) => setUserQuery(e.target.value)}
                className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-teal-400"
              />
            </div>
          </div>

          {/* Evidence Context JSON */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                Grounded Evidence Context (JSON)
              </label>
              <span className="text-[10px] text-slate-400">
                AI analyzes only facts present in this context
              </span>
            </div>
            <textarea
              rows={4}
              value={evidenceJson}
              onChange={(e) => setEvidenceJson(e.target.value)}
              className="w-full font-mono text-xs p-3 bg-black/40 border border-white/10 rounded-xl text-teal-300 focus:outline-none focus:border-teal-400"
            />
          </div>

          {/* Submit Action */}
          <div className="flex justify-end">
            <button
              onClick={handleRunAnalysis}
              disabled={loading}
              className="px-5 py-2.5 rounded-xl font-semibold text-xs bg-gradient-to-r from-teal-400 to-indigo-500 hover:from-teal-300 hover:to-indigo-400 text-[#090A0F] shadow-lg shadow-teal-500/20 transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {loading ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-[#090A0F] border-t-transparent rounded-full animate-spin"></span>
                  <span>Synthesizing Evidence...</span>
                </>
              ) : (
                <>
                  <span>⚡</span>
                  <span>Generate AI Assessment</span>
                </>
              )}
            </button>
          </div>

          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs rounded-xl">
              {error}
            </div>
          )}

          {/* Analysis Results Display */}
          {analysisResult && (
            <div className="p-5 rounded-2xl bg-white/[0.03] border border-teal-500/30 space-y-4 animate-fade-in">
              <div className="flex items-start justify-between">
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <span>🎯</span> Evidence Summary
                </h3>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono uppercase bg-teal-500/10 text-teal-300 border border-teal-500/20">
                  Confidence: {analysisResult.confidence}
                </span>
              </div>
              <p className="text-sm text-slate-200 leading-relaxed bg-black/30 p-3 rounded-xl border border-white/5">
                {analysisResult.summary}
              </p>

              {/* Extracted Evidence */}
              {analysisResult.evidence_extracted?.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                    Verified Grounded Facts:
                  </h4>
                  <ul className="list-disc list-inside space-y-1 text-xs text-slate-300">
                    {analysisResult.evidence_extracted.map((ev, idx) => (
                      <li key={idx}>{ev}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* MITRE ATT&CK */}
              {analysisResult.mitre_techniques?.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-400 mb-2">
                    MITRE ATT&CK Mapping:
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {analysisResult.mitre_techniques.map((tech, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 rounded-lg text-xs font-mono bg-indigo-500/10 border border-indigo-500/20 text-indigo-300"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Inferences */}
              {analysisResult.inferences?.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400 mb-2">
                    Investigative Inferences:
                  </h4>
                  <ul className="space-y-1 text-xs text-slate-300">
                    {analysisResult.inferences.map((inf, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-amber-400">›</span>
                        <span>{inf}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Recommendations */}
              {analysisResult.recommendations?.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-teal-400 mb-2">
                    Prioritized Next Steps & Remediation:
                  </h4>
                  <ul className="space-y-1.5 text-xs text-slate-300">
                    {analysisResult.recommendations.map((rec, idx) => (
                      <li key={idx} className="flex items-start gap-2 bg-teal-500/5 p-2 rounded-lg border border-teal-500/10">
                        <span className="text-teal-400 font-bold">{idx + 1}.</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AiCyberAssistantModal;
