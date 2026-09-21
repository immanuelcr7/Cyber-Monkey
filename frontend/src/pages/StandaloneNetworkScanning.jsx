import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { runStandaloneNmap } from '../services/api';

const StandaloneNetworkScanning = () => {
  const [target, setTarget] = useState('');
  const [scanProfile, setScanProfile] = useState('service_detection');
  const [authConfirmed, setAuthConfirmed] = useState(false);
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [scanResult, setScanResult] = useState(null);

  const profiles = [
    { value: 'service_detection', label: 'Service & OS Version Detection (-sV)' },
    { value: 'quick_scan', label: 'Quick Fast Scan (-F)' },
    { value: 'full_scan', label: 'All Ports Range Scan (-p-)' }
  ];

  const handleRunScan = async (e) => {
    e.preventDefault();
    if (!target.trim()) {
      setError('Please enter a target IP address or hostname.');
      return;
    }
    if (!authConfirmed) {
      setError('Explicit authorization confirmation is required before launching a scan.');
      return;
    }

    try {
      setLoading(true);
      setError('');
      setScanResult(null);

      const data = await runStandaloneNmap(target.trim(), scanProfile, authConfirmed);
      setScanResult(data);
    } catch (err) {
      if (err.response && err.response.data && err.response.data.detail) {
        setError(err.response.data.detail);
      } else {
        setError('Scan execution failed. Verify backend service availability.');
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
              CYBER MONKEY &nbsp;/&nbsp; <Link to="/pentest" className="hover:text-white">PENTEST</Link> &nbsp;/&nbsp; <span className="text-white">NETWORK SCANNING</span>
            </span>
          </div>
          <Link to="/pentest" className="text-xs text-teal-400 hover:underline">
            Back to Dashboard
          </Link>
        </div>

        {/* Hero Header */}
        <div className="mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-500/10 border border-teal-500/20 text-teal-300 text-xs font-semibold uppercase tracking-wider mb-3">
            📡 Standalone Quick Scanner
          </div>
          <h1 className="text-3xl md:text-4xl font-black text-slate-100 mb-2">
            Network Scanning
          </h1>
          <p className="text-slate-400 text-sm">
            Perform standalone port discovery and service detection without requiring an Assessment.
          </p>
        </div>

        {/* Scan Input Form */}
        <div className="p-6 rounded-2xl cyber-glass border border-white/5 mb-8">
          <form onSubmit={handleRunScan} className="space-y-6">
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                Target IP / Hostname <span className="text-rose-400">*</span>
              </label>
              <input 
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. 192.168.1.35 or scanme.nmap.org"
                className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-teal-400 transition-colors text-sm font-mono"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                  Scan Profile
                </label>
                <select
                  value={scanProfile}
                  onChange={(e) => setScanProfile(e.target.value)}
                  className="w-full px-4 py-3 rounded-xl bg-[#0F111A] border border-white/10 text-white focus:outline-none focus:border-teal-400 text-sm"
                >
                  {profiles.map(p => (
                    <option key={p.value} value={p.value}>{p.label}</option>
                  ))}
                </select>
              </div>

              <div className="flex items-end">
                <label className="flex items-center gap-3 p-3.5 rounded-xl bg-white/5 border border-white/10 w-full cursor-pointer hover:border-white/20 transition-colors">
                  <input 
                    type="checkbox"
                    checked={authConfirmed}
                    onChange={(e) => setAuthConfirmed(e.target.checked)}
                    className="w-4 h-4 rounded text-teal-400 focus:ring-0 bg-transparent border-white/20"
                  />
                  <span className="text-xs text-slate-300 font-medium">
                    I confirm explicit authorization to scan this target.
                  </span>
                </label>
              </div>
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
                  Executing Standalone Nmap Scan...
                </>
              ) : (
                '🚀 Start Standalone Scan'
              )}
            </button>
          </form>
        </div>

        {/* Scan Results Display */}
        {scanResult && (
          <div className="p-6 rounded-2xl cyber-glass border border-white/5 space-y-6 animate-fadeIn">
            <div className="flex items-center justify-between border-b border-white/5 pb-4">
              <div>
                <h3 className="text-xl font-bold text-slate-100">Scan Results: {scanResult.target}</h3>
                <p className="text-xs text-slate-400 mt-0.5">Profile: {scanResult.scan_profile || scanProfile}</p>
              </div>
              <span className={`px-3 py-1 text-xs font-bold rounded-full ${
                scanResult.status === 'completed' 
                  ? 'bg-teal-500/10 text-teal-300 border border-teal-500/20' 
                  : 'bg-rose-500/10 text-rose-300 border border-rose-500/20'
              }`}>
                {scanResult.status ? scanResult.status.toUpperCase() : 'COMPLETED'}
              </span>
            </div>

            {/* Ports Table */}
            <div>
              <h4 className="text-sm font-bold uppercase tracking-wider text-slate-300 mb-3">
                Discovered Ports ({scanResult.ports ? scanResult.ports.length : 0})
              </h4>
              {scanResult.ports && scanResult.ports.length > 0 ? (
                <div className="overflow-x-auto rounded-xl border border-white/5">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-white/5 text-slate-400 font-mono border-b border-white/5">
                      <tr>
                        <th className="p-3">Port</th>
                        <th className="p-3">Protocol</th>
                        <th className="p-3">State</th>
                        <th className="p-3">Service</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono text-slate-200">
                      {scanResult.ports.map((p, idx) => (
                        <tr key={idx} className="hover:bg-white/5">
                          <td className="p-3 text-teal-400 font-bold">{p.port}</td>
                          <td className="p-3 uppercase">{p.protocol || 'tcp'}</td>
                          <td className="p-3">
                            <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                              {p.state}
                            </span>
                          </td>
                          <td className="p-3">{p.service || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-xs text-slate-400 italic">No open ports identified or target filtered.</p>
              )}
            </div>

            {/* Raw Command Output */}
            {scanResult.raw_output && (
              <div>
                <h4 className="text-sm font-bold uppercase tracking-wider text-slate-300 mb-2">
                  Raw Output
                </h4>
                <pre className="p-4 rounded-xl bg-[#050609] border border-white/5 text-xs text-emerald-400 font-mono overflow-x-auto max-h-80 leading-relaxed whitespace-pre-wrap">
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

export default StandaloneNetworkScanning;
