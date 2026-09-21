import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { runStandaloneNikto } from '../services/api';

const StandaloneWebTesting = () => {
  const [target, setTarget] = useState('');
  const [port, setPort] = useState('80');
  const [authConfirmed, setAuthConfirmed] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [scanResult, setScanResult] = useState(null);

  const handleRunNikto = async (e) => {
    e.preventDefault();
    if (!target.trim()) {
      setError('Please enter a target IP address or hostname.');
      return;
    }
    const p = parseInt(port, 10);
    if (isNaN(p) || p < 1 || p > 65535) {
      setError('Port must be a valid integer between 1 and 65535.');
      return;
    }
    if (!authConfirmed) {
      setError('Explicit authorization confirmation is required before scanning.');
      return;
    }

    try {
      setLoading(true);
      setError('');
      setScanResult(null);

      const data = await runStandaloneNikto(target.trim(), p, authConfirmed);
      setScanResult(data);
    } catch (err) {
      if (err.response && err.response.data && err.response.data.detail) {
        setError(err.response.data.detail);
      } else {
        setError('Nikto web scan failed. Check backend service logs.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen p-6 md:p-12 relative overflow-hidden bg-[#090A0F] text-slate-100">
      <div className="absolute top-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-indigo-500/10 blur-[120px] pointer-events-none"></div>

      <div className="max-w-5xl mx-auto z-10 relative">
        
        {/* Navigation Breadcrumb */}
        <div className="flex items-center justify-between mb-8 border-b border-white/5 pb-6">
          <div className="flex items-center gap-3">
            <Link to="/" className="w-8 h-8 rounded-lg bg-gradient-to-tr from-teal-400 to-indigo-500 flex items-center justify-center font-bold text-lg text-[#090A0F]">
              🐒
            </Link>
            <span className="font-bold tracking-wider text-sm text-slate-400">
              CYBER MONKEY &nbsp;/&nbsp; <Link to="/pentest" className="hover:text-white">PENTEST</Link> &nbsp;/&nbsp; <span className="text-white">WEB TESTING</span>
            </span>
          </div>
          <Link to="/pentest" className="text-xs text-teal-400 hover:underline">
            Back to Dashboard
          </Link>
        </div>

        {/* Hero Header */}
        <div className="mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-500/10 border border-teal-500/20 text-teal-300 text-xs font-semibold uppercase tracking-wider mb-3">
            🌐 Standalone Web Scanner (Nikto Engine)
          </div>
          <h1 className="text-3xl md:text-4xl font-black text-slate-100 mb-2">
            Web Application Testing
          </h1>
          <p className="text-slate-400 text-sm">
            Scan web servers, endpoints, and headers for misconfigurations and vulnerabilities without an Assessment.
          </p>
        </div>

        {/* Form */}
        <div className="p-6 rounded-2xl cyber-glass border border-white/5 mb-8">
          <form onSubmit={handleRunNikto} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="md:col-span-2">
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                  Target Host IP / Domain <span className="text-rose-400">*</span>
                </label>
                <input 
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g. 192.168.1.35 or example.com"
                  className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-teal-400 text-sm font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                  Port Number (1 - 65535) <span className="text-rose-400">*</span>
                </label>
                <input 
                  type="number"
                  min="1"
                  max="65535"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white focus:outline-none focus:border-teal-400 text-sm font-mono"
                />
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
                  I confirm explicit authorization to perform web application testing on this host.
                </span>
              </label>
            </div>

            {error && (
              <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm">
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
                  Executing Nikto Web Scan...
                </>
              ) : (
                '🌐 Start Nikto Web Scan'
              )}
            </button>
          </form>
        </div>

        {/* Results */}
        {scanResult && (
          <div className="p-6 rounded-2xl cyber-glass border border-white/5 space-y-6 animate-fadeIn">
            <div className="flex items-center justify-between border-b border-white/5 pb-4">
              <div>
                <h3 className="text-xl font-bold text-slate-100">Nikto Scan: {scanResult.target}:{scanResult.port}</h3>
                <p className="text-xs text-slate-400 mt-0.5">Discovered Findings: {scanResult.finding_count || 0}</p>
              </div>
              <span className="px-3 py-1 text-xs font-bold rounded-full bg-teal-500/10 text-teal-300 border border-teal-500/20">
                {scanResult.status ? scanResult.status.toUpperCase() : 'COMPLETED'}
              </span>
            </div>

            {/* Findings List */}
            {scanResult.findings && scanResult.findings.length > 0 ? (
              <div className="space-y-3">
                {scanResult.findings.map((f, idx) => (
                  <div key={idx} className="p-4 rounded-xl bg-white/5 border border-white/5 flex items-start gap-4">
                    <span className="px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                      {f.severity || 'INFO'}
                    </span>
                    <div>
                      <h4 className="text-sm font-bold text-slate-200">{f.title || f.nikto_id}</h4>
                      <p className="text-xs text-slate-400 font-mono mt-1">{f.description || f.endpoint}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-400 italic">No vulnerability findings detected by Nikto.</p>
            )}

            {/* Raw Log */}
            {scanResult.raw_output && (
              <div>
                <h4 className="text-sm font-bold uppercase tracking-wider text-slate-300 mb-2">Raw Nikto Log</h4>
                <pre className="p-4 rounded-xl bg-[#050609] border border-white/5 text-xs text-teal-300 font-mono overflow-x-auto max-h-80 whitespace-pre-wrap">
                  {scanResult.raw_output}
                </pre>
              </div>
            )}
          </div>
        )}

      </div>
    </div>
  );
};

export default StandaloneWebTesting;
