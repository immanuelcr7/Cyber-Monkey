import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';

const Home = () => {
  const navigate = useNavigate();
  const [backendStatus, setBackendStatus] = useState('checking'); // checking, online, offline
  const [errorDetails, setErrorDetails] = useState('');

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
  };

  useEffect(() => {
    checkHealth();
  }, []);

  return (
    <div className="min-h-screen flex flex-col justify-between p-6 md:p-12 relative overflow-hidden">
      
      {/* Decorative cyber grid/shapes */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] rounded-full bg-teal-500/10 blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full bg-indigo-500/10 blur-[120px] pointer-events-none"></div>
      
      {/* Top Navigation / Brand */}
      <header className="w-full max-w-7xl mx-auto flex items-center justify-between z-10">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-teal-400 to-indigo-500 flex items-center justify-center shadow-lg shadow-teal-500/20">
            <span className="text-xl font-extrabold text-[#090A0F] font-mono">🐒</span>
          </div>
          <span className="font-bold text-xl tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-teal-400 to-indigo-400">
            CYBER MONKEY
          </span>
        </div>
        
        <div>
          <button 
            id="btn_retry_health"
            onClick={checkHealth}
            className="px-4 py-2 text-sm rounded-lg border border-teal-500/30 hover:border-teal-400 bg-teal-500/5 hover:bg-teal-500/10 text-teal-300 font-medium transition-all duration-300 cursor-pointer flex items-center gap-2"
          >
            <span className={`w-2 h-2 rounded-full ${backendStatus === 'online' ? 'bg-teal-400 animate-pulse' : 'bg-rose-400 animate-ping'}`}></span>
            Sync Status
          </button>
        </div>
      </header>

      {/* Main Content Hero */}
      <main className="w-full max-w-4xl mx-auto my-auto flex flex-col items-center text-center z-10 py-12">
        
        {/* Decorative Badge */}
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-xs font-semibold uppercase tracking-widest mb-6 animate-pulse">
          ⚡ System Core Ready
        </div>

        {/* Brand Main Headings */}
        <h1 className="text-5xl md:text-8xl font-black tracking-tight mb-4">
          <span className="bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-teal-400">
            Cyber Monkey
          </span>
        </h1>
        
        <h2 className="text-xl md:text-3xl font-medium tracking-wide text-indigo-300/90 max-w-2xl mb-12">
          Penetration Testing Platform
        </h2>

        {/* Health Check Diagnostics Card */}
        <div className="w-full max-w-md p-6 rounded-2xl cyber-glass relative overflow-hidden transition-all duration-300 hover:shadow-2xl hover:shadow-teal-500/5">
          <div className="absolute top-0 left-0 w-1.5 h-full bg-gradient-to-b from-teal-400 to-indigo-500"></div>
          
          <h3 className="text-left text-sm font-semibold tracking-wider text-slate-400 uppercase mb-4">
            Connection Diagnostics
          </h3>

          <div className="flex items-center justify-between border-b border-white/5 pb-4 mb-4">
            <span className="text-slate-300 text-sm">Target Server:</span>
            <span className="font-mono text-xs text-slate-400 bg-white/5 px-2.5 py-1 rounded">
              {import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api'}
            </span>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-slate-300 text-sm">Status Indicator:</span>
            
            {backendStatus === 'checking' && (
              <span id="status_checking" className="inline-flex items-center gap-1.5 text-indigo-400 font-medium text-sm">
                <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Resolving API...
              </span>
            )}

            {backendStatus === 'online' && (
              <span id="status_online" className="inline-flex items-center gap-1.5 text-teal-400 font-bold text-sm bg-teal-500/10 px-3 py-1 rounded-full border border-teal-500/20 shadow-[0_0_15px_rgba(20,184,166,0.15)]">
                <span className="w-2.5 h-2.5 rounded-full bg-teal-400 animate-pulse"></span>
                API Connected
              </span>
            )}

            {backendStatus === 'offline' && (
              <span id="status_offline" className="inline-flex items-center gap-1.5 text-rose-400 font-bold text-sm bg-rose-500/10 px-3 py-1 rounded-full border border-rose-500/20">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-400"></span>
                Offline
              </span>
            )}
          </div>

          {backendStatus === 'offline' && (
            <div className="mt-4 p-3 bg-rose-500/5 rounded-lg border border-rose-500/10 text-rose-300 text-xs text-left font-mono">
              <strong>Error Details:</strong> {errorDetails}
            </div>
          )}
        </div>

        <p className="mt-8 text-xs text-slate-500 max-w-sm leading-relaxed mb-12">
          System operational. Awaiting orchestration scripts and tool integrations. Ensure backend Docker Compose PostgreSQL is up and local ASGI application is running.
        </p>

        {/* Security Roles / Cybersecurity Workspaces */}
        <section className="w-full max-w-2xl mt-4 text-left">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4 text-center sm:text-left">
            Cybersecurity Workspaces
          </h3>
          
          <div className="p-6 rounded-2xl cyber-glass relative overflow-hidden transition-all duration-300 hover:border-teal-500/30 hover:shadow-lg hover:shadow-teal-500/5 group">
            <div className="absolute top-0 left-0 w-1.5 h-full bg-gradient-to-b from-teal-400 to-indigo-500"></div>
            
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
              <div className="space-y-2">
                <div className="flex items-center gap-2.5">
                  <span className="text-2xl" role="img" aria-label="shield">🛡️</span>
                  <h4 className="text-lg font-bold text-slate-200">
                    Penetration Testing
                  </h4>
                </div>
                <p className="text-slate-400 text-sm leading-relaxed max-w-lg">
                  Conduct authorized security assessments, manage targets, perform reconnaissance, analyze vulnerabilities, and generate professional penetration testing reports.
                </p>
              </div>
              
              <div className="shrink-0">
                <button
                  id="btn_open_pentest"
                  onClick={() => navigate('/pentest')}
                  className="px-5 py-2.5 text-xs font-semibold rounded-lg bg-teal-400 hover:bg-teal-300 text-[#090A0F] cursor-pointer shadow-lg shadow-teal-500/10 transition-all duration-300 group-hover:scale-105"
                >
                  Open Penetration Testing &rarr;
                </button>
              </div>
            </div>
          </div>
        </section>

      </main>

      {/* Footer */}
      <footer className="w-full max-w-7xl mx-auto flex items-center justify-between text-xs text-slate-500 border-t border-white/5 pt-6 z-10">
        <div>
          &copy; {new Date().getFullYear()} Cyber Monkey Project. All Rights Reserved.
        </div>
        <div className="flex gap-4">
          <span className="hover:text-teal-400 transition-colors">Privacy Policy</span>
          <span className="hover:text-teal-400 transition-colors">Documentation</span>
        </div>
      </footer>
    </div>
  );
};

export default Home;
