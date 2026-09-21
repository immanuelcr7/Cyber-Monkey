import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { runStandaloneNuclei, runStandaloneNikto } from '../services/api';

const StandaloneVulnerabilities = () => {
  const [target, setTarget] = useState('');
  const [engine, setEngine] = useState('nuclei'); // nuclei, nikto
  const [profile, setProfile] = useState('BASIC');
  const [port, setPort] = useState('80');
  const [authConfirmed, setAuthConfirmed] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  const handleRunScan = async (e) => {
    e.preventDefault();
    if (!target.trim()) {
      setError('Please enter a target URL or host IP.');
      return;
    }
    if (!authConfirmed) {
      setError('Explicit authorization confirmation is required before scanning.');
      return;
    }

    try {
      setLoading(true);
      setError('');
      setResult(null);

      let data;
      if (engine === 'nuclei') {
        data = await runStandaloneNuclei(target.trim(), profile, authConfirmed);
      } else {
        const p = parseInt(port, 10) || 80;
        data = await runStandaloneNikto(target.trim(), p, authConfirmed);
      }
      setResult(data);
    } catch (err) {
      if (err.response && err.response.data && err.response.data.detail) {
        setError(err.response.data.detail);
      } else {
        setError('Vulnerability scan failed. Check backend service execution.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen p-6 md:p-12 relative overflow-hidden bg-[#090A0F] text-slate-100">
      <div className="absolute top-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-teal-500/10 blur-[120px] pointer-events-none"></div>

      <div className="max-w-5xl mx-auto z-10 relative">
        
        {/* Navigation Breadcrumb */}
        <div className="flex items-center justify-between mb-8 border-b border-white/5 pb-6">
          <div className="flex items-center gap-3">
            <Link to="/" className="w-8 h-8 rounded-lg bg-gradient-to-tr from-teal-400 to-indigo-500 flex items-center justify-center font-bold text-lg text-[#090A0F]">
              🐒
            </Link>
            <span className="font-bold tracking-wider text-sm text-slate-400">
              CYBER MONKEY &nbsp;/&nbsp; <Link to="/pentest" className="hover:text-white">PENTEST</Link> &nbsp;/&nbsp; <span className="text-white">VULNERABILITY ASSESSMENT</span>
            </span>
          </div>
          <Link to="/pentest" className="text-xs text-teal-400 hover:underline">
            Back to Dashboard
          </Link>
        </div>

        {/* Hero Header */}
        <div className="mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-500/10 border border-teal-500/20 text-teal-300 text-xs font-semibold uppercase tracking-wider mb-3">
            🛡️ Standalone Vulnerability Scanner
          </div>
          <h1 className="text-3xl md:text-4xl font-black text-slate-100 mb-2">
            Vulnerability Assessment
          </h1>
          <p className="text-slate-400 text-sm">
            Launch Nuclei template-based security scans or Nikto web misconfiguration checks without an Assessment.
          </p>
        </div>

        {/* Form */}
        <div className="p-6 rounded-2xl cyber-glass border border-white/5 mb-8">
          <form onSubmit={handleRunScan} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                  Scanner Engine
                </label>
                <select
                  value={engine}
                  onChange={(e) => setEngine(e.target.value)}
                  className="w-full px-4 py-3 rounded-xl bg-[#0F111A] border border-white/10 text-white focus:outline-none focus:border-teal-400 text-sm"
                >
                  <option value="nuclei">Nuclei (Vulnerability Templates)</option>
                  <option value="nikto">Nikto (Web Server Scanner)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                  Target Host / URL <span className="text-rose-400">*</span>
                </label>
                <input 
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder={engine === 'nuclei' ? 'e.g. https://example.com' : 'e.g. 192.168.1.35'}
                  className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-teal-400 text-sm font-mono"
                />
              </div>

              {engine === 'nuclei' ? (
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                    Template Profile
                  </label>
                  <select
                    value={profile}
                    onChange={(e) => setProfile(e.target.value)}
                    className="w-full px-4 py-3 rounded-xl bg-[#0F111A] border border-white/10 text-white focus:outline-none focus:border-teal-400 text-sm"
                  >
                    <option value="BASIC">Basic Scans</option>
                    <option value="FULL">Full Comprehensive</option>
                    <option value="CVE">CVE Specific</option>
                  </select>
                </div>
              ) : (
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                    Port Number
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
              )}
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
                  I confirm explicit authorization to run vulnerability assessment on this target.
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
                  Executing Vulnerability Assessment...
                </>
              ) : (
                '🛡️ Start Vulnerability Scan'
              )}
            </button>
          </form>
        </div>

        {/* Results */}
        {result && (
          <div className="p-6 rounded-2xl cyber-glass border border-white/5 space-y-4 animate-fadeIn">
            <h3 className="text-xl font-bold text-slate-100 border-b border-white/5 pb-3">Scan Output</h3>
            <pre className="p-4 rounded-xl bg-[#050609] border border-white/5 text-xs text-teal-300 font-mono overflow-x-auto max-h-96 whitespace-pre-wrap">
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        )}

      </div>
    </div>
  );
};

export default StandaloneVulnerabilities;
