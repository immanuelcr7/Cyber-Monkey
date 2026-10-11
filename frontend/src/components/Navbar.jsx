import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const Navbar = ({ onOpenAi, onOpenIntegrations, activeWorkspaceTitle }) => {
  const location = useLocation();

  const workspaces = [
    { name: 'SOC Analyst', path: '/soc', icon: '🚨' },
    { name: 'Penetration Testing', path: '/pentest', icon: '🎯' },
    { name: 'OSINT', path: '/osint', icon: '🌐' },
    { name: 'Malware Analysis', path: '/malware-analysis', icon: '🦠' },
    { name: 'Digital Forensics', path: '/digital-forensics', icon: '🔬' },
    { name: 'Network Monitoring', path: '/network-monitoring', icon: '📡' },
  ];

  return (
    <header className="w-full max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4 mb-8 border-b border-white/5 pb-5 z-20">
      <div className="flex items-center gap-4 w-full md:w-auto justify-between md:justify-start">
        <Link to="/" className="flex items-center gap-3 group">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-teal-400 to-indigo-500 flex items-center justify-center shadow-lg shadow-teal-500/20 group-hover:scale-105 transition-transform">
            <span className="text-xl font-extrabold text-[#090A0F] font-mono">🐒</span>
          </div>
          <div>
            <div className="font-black text-lg tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-teal-400 to-indigo-400">
              CYBER MONKEY
            </div>
            <div className="text-[10px] uppercase font-mono tracking-widest text-slate-400">
              {activeWorkspaceTitle ? activeWorkspaceTitle : 'Cybersecurity OS'}
            </div>
          </div>
        </Link>
      </div>

      {/* Navigation Quick Links */}
      <nav className="flex items-center gap-1.5 overflow-x-auto w-full md:w-auto py-1 scrollbar-none">
        <Link
          to="/"
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
            location.pathname === '/'
              ? 'bg-white/10 text-white font-bold'
              : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
          }`}
        >
          Dashboard
        </Link>
        {workspaces.map((ws) => {
          const isActive = location.pathname.startsWith(ws.path);
          return (
            <Link
              key={ws.path}
              to={ws.path}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 whitespace-nowrap transition-all ${
                isActive
                  ? 'bg-teal-500/20 text-teal-300 border border-teal-500/30 font-semibold shadow-sm shadow-teal-500/10'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <span>{ws.icon}</span>
              <span>{ws.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* Utility Actions */}
      <div className="flex items-center gap-2.5 shrink-0">
        {onOpenIntegrations && (
          <button
            onClick={onOpenIntegrations}
            title="Integrations & Engine Status"
            className="px-3 py-1.5 text-xs rounded-lg border border-white/10 hover:border-teal-500/40 bg-white/5 hover:bg-white/10 text-slate-300 hover:text-teal-300 transition-all flex items-center gap-1.5 cursor-pointer"
          >
            <span>🔌</span>
            <span className="hidden sm:inline">Integrations</span>
          </button>
        )}
        {onOpenAi && (
          <button
            onClick={onOpenAi}
            className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-gradient-to-r from-teal-400 to-indigo-500 hover:from-teal-300 hover:to-indigo-400 text-[#090A0F] shadow-lg shadow-teal-500/15 transition-all flex items-center gap-1.5 cursor-pointer"
          >
            <span>🧠</span>
            <span>AI Cyber Assistant</span>
          </button>
        )}
      </div>
    </header>
  );
};

export default Navbar;
