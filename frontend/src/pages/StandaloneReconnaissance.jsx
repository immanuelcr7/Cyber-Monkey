import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { runStandaloneReconScan } from '../services/api';

const StandaloneReconnaissance = () => {
  const [target, setTarget] = useState('');
  const [tool, setTool] = useState('theHarvester'); // theHarvester, subfinder, dns, shodan
  const [authConfirmed, setAuthConfirmed] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  const isIpAddress = (val) => {
    if (!val) return false;
    const clean = val.trim().split(':')[0];
    const parts = clean.split('.');
    return parts.length === 4 && parts.every(p => /^\d+$/.test(p) && parseInt(p, 10) >= 0 && parseInt(p, 10) <= 255);
  };

  const handleRunRecon = async (e) => {
    e.preventDefault();
    const targetClean = target.trim();
    if (!targetClean) {
      setError('Please enter a target domain or IP address.');
      return;
    }
    if (!authConfirmed) {
      setError('Explicit authorization confirmation is required before scanning.');
      return;
    }

    const toolLower = tool.toLowerCase();

    // Task 3: Domain vs IP Target Validation
    if (toolLower === 'theharvester' && isIpAddress(targetClean)) {
      setError('theHarvester requires a domain target (e.g., example.com).');
      return;
    }
    if (toolLower === 'subfinder' && isIpAddress(targetClean)) {
      setError('Subfinder requires a domain target (e.g., example.com).');
      return;
    }
    if (toolLower === 'dns' && isIpAddress(targetClean)) {
      setError('DNS lookup requires a domain target (e.g., example.com).');
      return;
    }

    try {
      setLoading(true);
      setError('');
      setResult(null);

      const data = await runStandaloneReconScan(targetClean, tool, authConfirmed);
      setResult(data);
    } catch (err) {
      if (err.response) {
        const status = err.response.status;
        const detail = err.response.data?.detail;

        if (status === 404) {
          setError('Reconnaissance API endpoint is unavailable (404 Not Found).');
        } else if (status === 400) {
          setError(detail || 'Invalid target for selected reconnaissance tool.');
        } else if (status === 401 || status === 403) {
          setError('Authorization required to perform this reconnaissance scan.');
        } else if (status === 503) {
          setError(detail || 'Selected reconnaissance service is unavailable on the backend host.');
        } else {
          setError(detail || `Reconnaissance scan failed with status code ${status}.`);
        }
      } else if (err.request) {
        setError('Backend connection unavailable. Please make sure the Cyber Monkey API is running.');
      } else {
        setError(err.message || 'An unexpected error occurred during scan execution.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen p-6 md:p-12 relative overflow-hidden bg-[#090A0F] text-slate-100">
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-teal-500/10 blur-[120px] pointer-events-none"></div>

      <div className="max-w-5xl mx-auto z-10 relative">
        
        {/* Navigation Breadcrumb */}
        <div className="flex items-center justify-between mb-8 border-b border-white/5 pb-6">
          <div className="flex items-center gap-3">
            <Link to="/" className="w-8 h-8 rounded-lg bg-gradient-to-tr from-teal-400 to-indigo-500 flex items-center justify-center font-bold text-lg text-[#090A0F]">
              🐒
            </Link>
            <span className="font-bold tracking-wider text-sm text-slate-400">
              CYBER MONKEY &nbsp;/&nbsp; <Link to="/pentest" className="hover:text-white">PENTEST</Link> &nbsp;/&nbsp; <span className="text-white">RECONNAISSANCE</span>
            </span>
          </div>
          <Link to="/pentest" className="text-xs text-teal-400 hover:underline">
            Back to Dashboard
          </Link>
        </div>

        {/* Hero Header */}
        <div className="mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-500/10 border border-teal-500/20 text-teal-300 text-xs font-semibold uppercase tracking-wider mb-3">
            🔍 Standalone Reconnaissance Tool
          </div>
          <h1 className="text-3xl md:text-4xl font-black text-slate-100 mb-2">
            Reconnaissance & OSINT
          </h1>
          <p className="text-slate-400 text-sm">
            Execute passive & active intelligence gathering against verified assets without requiring an Assessment.
          </p>
        </div>

        {/* Form */}
        <div className="p-6 rounded-2xl cyber-glass border border-white/5 mb-8">
          <form onSubmit={handleRunRecon} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                  Recon Tool Selection
                </label>
                <select
                  value={tool}
                  onChange={(e) => {
                    setTool(e.target.value);
                    setError('');
                  }}
                  className="w-full px-4 py-3 rounded-xl bg-[#0F111A] border border-white/10 text-white focus:outline-none focus:border-teal-400 text-sm font-semibold"
                >
                  <option value="theHarvester">theHarvester (OSINT Intelligence)</option>
                  <option value="subfinder">Subfinder (Subdomain Discovery)</option>
                  <option value="dns">DNS Records Lookup</option>
                  <option value="shodan">Shodan Host Intelligence</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                  Target Domain / Host <span className="text-rose-400">*</span>
                </label>
                <input 
                  type="text"
                  value={target}
                  onChange={(e) => {
                    setTarget(e.target.value);
                    setError('');
                  }}
                  placeholder={tool.toLowerCase() === 'shodan' ? 'e.g. example.com or 192.168.1.35' : 'e.g. example.com'}
                  className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-teal-400 text-sm font-mono"
                />
                <p className="text-[11px] text-slate-400 mt-1.5">
                  {tool.toLowerCase() === 'theharvester' || tool.toLowerCase() === 'subfinder' || tool.toLowerCase() === 'dns' ? (
                    <span className="text-amber-300/80 font-medium">⚠️ Note: {tool} requires a valid domain target (e.g. example.com).</span>
                  ) : (
                    <span>Supports domain names and IP addresses.</span>
                  )}
                </p>
              </div>
            </div>

            <div className="flex items-center">
              <label className="flex items-center gap-3 p-3.5 rounded-xl bg-white/5 border border-white/10 w-full cursor-pointer hover:border-white/20 transition-colors">
                <input 
                  type="checkbox"
                  checked={authConfirmed}
                  onChange={(e) => setAuthConfirmed(e.target.checked)}
                  className="w-4 h-4 rounded text-teal-400 focus:ring-0 bg-transparent border-white/20"
                />
                <span className="text-xs text-slate-300 font-medium">
                  I confirm explicit authorization to gather intelligence on this target.
                </span>
              </label>
            </div>

            {error && (
              <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm font-medium">
                ⚠️ {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3.5 px-6 rounded-xl font-bold text-sm bg-gradient-to-r from-teal-400 to-indigo-500 hover:from-teal-300 hover:to-indigo-400 text-[#090A0F] shadow-lg shadow-teal-500/10 cursor-pointer disabled:opacity-50 transition-all flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-5 w-5 text-[#090A0F]" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Executing {tool} Scan...
                </>
              ) : (
                '🔍 Run Recon Scan'
              )}
            </button>
          </form>
        </div>

        {/* Results */}
        {result && (
          <div className="p-6 rounded-2xl cyber-glass border border-white/5 space-y-6 animate-fadeIn">
            <div className="flex items-center justify-between border-b border-white/5 pb-4">
              <div>
                <h3 className="text-xl font-bold text-slate-100">Recon Scan Results: {target}</h3>
                <p className="text-xs text-slate-400 mt-0.5">Tool Used: <span className="font-mono text-teal-300">{tool}</span></p>
              </div>
              <span className="px-3 py-1 text-xs font-bold rounded-full bg-teal-500/10 text-teal-300 border border-teal-500/20 uppercase">
                {result.status || 'COMPLETED'}
              </span>
            </div>

            {/* theHarvester Structured Results */}
            {tool.toLowerCase() === 'theharvester' && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 text-center">
                  <div className="p-3 rounded-xl bg-white/5 border border-white/5">
                    <span className="block text-2xl font-black text-teal-400">{result.emails ? result.emails.length : 0}</span>
                    <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Emails Discovered</span>
                  </div>
                  <div className="p-3 rounded-xl bg-white/5 border border-white/5">
                    <span className="block text-2xl font-black text-indigo-400">{result.hosts ? result.hosts.length : 0}</span>
                    <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Hosts Discovered</span>
                  </div>
                  <div className="p-3 rounded-xl bg-white/5 border border-white/5">
                    <span className="block text-2xl font-black text-teal-300">{result.ips ? result.ips.length : 0}</span>
                    <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">IPs Discovered</span>
                  </div>
                  <div className="p-3 rounded-xl bg-white/5 border border-white/5">
                    <span className="block text-2xl font-black text-amber-400">{result.duration ? `${result.duration}s` : '—'}</span>
                    <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Execution Time</span>
                  </div>
                </div>

                {result.emails && result.emails.length > 0 && (
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">Emails</h4>
                    <div className="p-3 rounded-xl bg-white/5 border border-white/5 font-mono text-xs text-teal-300 space-y-1">
                      {result.emails.map((e, idx) => (
                        <div key={idx}>📧 {e}</div>
                      ))}
                    </div>
                  </div>
                )}

                {result.hosts && result.hosts.length > 0 && (
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">Hosts</h4>
                    <div className="p-3 rounded-xl bg-white/5 border border-white/5 font-mono text-xs text-indigo-300 space-y-1 max-h-48 overflow-y-auto">
                      {result.hosts.map((h, idx) => (
                        <div key={idx}>🌐 {h}</div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Raw Log Output */}
            {result.raw_output && (
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">Raw Execution Log</h4>
                <pre className="p-4 rounded-xl bg-[#050609] border border-white/5 text-xs text-teal-300 font-mono overflow-x-auto max-h-80 whitespace-pre-wrap leading-relaxed">
                  {result.raw_output}
                </pre>
              </div>
            )}

            {/* Structured Raw Output fallback */}
            {!result.raw_output && (
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">Response Data</h4>
                <pre className="p-4 rounded-xl bg-[#050609] border border-white/5 text-xs text-teal-300 font-mono overflow-x-auto max-h-80 whitespace-pre-wrap">
                  {JSON.stringify(result, null, 2)}
                </pre>
              </div>
            )}

          </div>
        )}

      </div>
    </div>
  );
};

export default StandaloneReconnaissance;
