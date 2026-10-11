import React, { useEffect, useState } from 'react';
import { getAllIntegrationsStatus } from '../services/api';

const IntegrationsModal = ({ isOpen, onClose }) => {
  const [integrations, setIntegrations] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getAllIntegrationsStatus();
      setIntegrations(data);
    } catch (err) {
      setError(err.message || 'Failed to load integrations status');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchStatus();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const renderBadge = (status) => {
    if (status === 'connected') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-teal-500/10 text-teal-300 border border-teal-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse"></span>
          Connected
        </span>
      );
    }
    if (status === 'not_configured') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-amber-500/10 text-amber-300 border border-amber-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
          Not Configured
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-rose-500/10 text-rose-300 border border-rose-500/20">
        <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
        Unavailable / Error
      </span>
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-4xl bg-[#0e1017] border border-white/10 rounded-2xl shadow-2xl p-6 md:p-8 relative max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-white/10">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <span>🔌</span> Central Tool Integrations Health
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Real connection status for all Cyber Monkey security engines and external APIs.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={fetchStatus}
              disabled={loading}
              className="px-3 py-1.5 text-xs rounded-lg border border-teal-500/30 hover:border-teal-400 bg-teal-500/10 text-teal-300 font-medium transition cursor-pointer"
            >
              {loading ? 'Testing...' : 'Refresh Status'}
            </button>
            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white flex items-center justify-center cursor-pointer text-lg font-bold"
            >
              &times;
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="overflow-y-auto py-6 pr-2 flex-1 space-y-4">
          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs rounded-xl">
              {error}
            </div>
          )}

          {loading && !integrations && (
            <div className="py-12 text-center text-slate-400 text-sm">
              Testing connectivity to backend services and external APIs...
            </div>
          )}

          {integrations && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.entries(integrations).map(([key, item]) => (
                <div
                  key={key}
                  className="p-4 rounded-xl bg-white/[0.03] border border-white/5 hover:border-white/10 transition"
                >
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div>
                      <h4 className="font-semibold text-slate-200 text-sm">{item.display_name}</h4>
                      <span className="text-[10px] font-mono text-slate-400">{key}</span>
                    </div>
                    {renderBadge(item.status)}
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    {item.error_message || 'Operational and responsive.'}
                  </p>
                  {item.details && typeof item.details === 'object' && Object.keys(item.details).length > 0 && (
                    <div className="mt-2 pt-2 border-t border-white/5 text-[11px] font-mono text-slate-400 flex flex-wrap gap-2">
                      {Object.entries(item.details).map(([k, v]) => (
                        <span key={k} className="bg-white/5 px-2 py-0.5 rounded text-slate-300">
                          {k}: {String(v)}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer info note */}
        <div className="pt-4 border-t border-white/10 flex items-center justify-between text-xs text-slate-400">
          <span>
            Honest reporting: Unconnected tools report <em>Not Configured</em> rather than fabricated telemetry.
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white font-medium cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default IntegrationsModal;
