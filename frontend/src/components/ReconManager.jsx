import React, { useEffect, useState, useCallback } from 'react';
import { 
  getTargets, 
  getNmapStatus, 
  startNmapScan, 
  getNmapScans,
  getSubfinderStatus,
  startSubfinderScan,
  getSubfinderScans,
  getDnsStatus,
  startDnsScan,
  getDnsScans,
  getTheHarvesterStatus,
  startTheHarvesterScan,
  getTheHarvesterScans,
  getShodanStatus,
  startShodanScan,
  getShodanScans
} from '../services/api';

const CollapsibleSection = ({ title, children, defaultOpen = false }) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  return (
    <div className="border border-white/5 rounded-2xl bg-white/5 overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-4 hover:bg-white/5 transition-colors cursor-pointer"
      >
        <span className="text-sm font-bold text-slate-200">{title}</span>
        <span className="text-slate-400 text-xs">{isOpen ? '▲' : '▼'}</span>
      </button>
      {isOpen && <div className="p-6 border-t border-white/5">{children}</div>}
    </div>
  );
};

const ReconManager = ({ assessmentId, assessment }) => {
  const [targets, setTargets] = useState([]);
  const [nmapStatus, setNmapStatus] = useState({ installed: false, version: null });
  const [scansHistory, setScansHistory] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);

  // Configuration form state
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [selectedScanProfile, setSelectedScanProfile] = useState('service_detection');

  // Loading and error states
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [scanLoading, setScanLoading] = useState(false);
  const [scanError, setScanError] = useState('');

  // Subfinder states
  const [subfinderStatus, setSubfinderStatus] = useState({ installed: false, version: null });
  const [subfinderHistory, setSubfinderHistory] = useState([]);
  const [selectedSubfinderScan, setSelectedSubfinderScan] = useState(null);
  const [selectedSubfinderTargetId, setSelectedSubfinderTargetId] = useState('');
  const [subfinderScanLoading, setSubfinderScanLoading] = useState(false);
  const [subfinderScanError, setSubfinderScanError] = useState('');

  // DNS states
  const [dnsStatus, setDnsStatus] = useState({ available: false, resolver: 'Unknown' });
  const [dnsHistory, setDnsHistory] = useState([]);
  const [selectedDnsScan, setSelectedDnsScan] = useState(null);
  const [selectedDnsTargetId, setSelectedDnsTargetId] = useState('');
  const [dnsScanLoading, setDnsScanLoading] = useState(false);
  const [dnsScanError, setDnsScanError] = useState('');

  // theHarvester states
  const [theharvesterStatus, setTheharvesterStatus] = useState({ available: false, path: '', version: null });
  const [theharvesterHistory, setTheharvesterHistory] = useState([]);
  const [selectedTheharvesterScan, setSelectedTheharvesterScan] = useState(null);
  const [selectedTheharvesterTargetId, setSelectedTheharvesterTargetId] = useState('');
  const [theharvesterScanLoading, setTheharvesterScanLoading] = useState(false);
  const [theharvesterScanError, setTheharvesterScanError] = useState('');

  // Shodan states
  const [shodanStatus, setShodanStatus] = useState({ configured: false, available: false });
  const [shodanHistory, setShodanHistory] = useState([]);
  const [selectedShodanScan, setSelectedShodanScan] = useState(null);
  const [selectedShodanTargetId, setSelectedShodanTargetId] = useState('');
  const [shodanScanLoading, setShodanScanLoading] = useState(false);
  const [shodanScanError, setShodanScanError] = useState('');

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError('');
      
      // 1. Fetch Nmap Status
      const statusData = await getNmapStatus();
      setNmapStatus(statusData);

      // 2. Fetch targets
      const targetsData = await getTargets(assessmentId);
      setTargets(targetsData);

      // 3. Fetch scan history
      const historyData = await getNmapScans(assessmentId);
      setScansHistory(historyData);

      // If we already have scans, select the latest one as active
      if (historyData.length > 0) {
        setSelectedScan(historyData[0]);
      }

      // 4. Fetch Subfinder Status
      const subfinderStatusData = await getSubfinderStatus();
      setSubfinderStatus(subfinderStatusData);

      // 5. Fetch Subfinder history
      const subfinderHistoryData = await getSubfinderScans(assessmentId);
      setSubfinderHistory(subfinderHistoryData);

      // If we already have Subfinder scans, select the latest one as active
      if (subfinderHistoryData.length > 0) {
        setSelectedSubfinderScan(subfinderHistoryData[0]);
      }

      // 6. Fetch DNS Status
      const dnsStatusData = await getDnsStatus();
      setDnsStatus(dnsStatusData);

      // 7. Fetch DNS history
      const dnsHistoryData = await getDnsScans(assessmentId);
      setDnsHistory(dnsHistoryData);

      // If we already have DNS scans, select the latest one as active
      if (dnsHistoryData.length > 0) {
        setSelectedDnsScan(dnsHistoryData[0]);
      }

      // 8. Fetch theHarvester Status
      const theharvesterStatusData = await getTheHarvesterStatus();
      setTheharvesterStatus(theharvesterStatusData);

      // 9. Fetch theHarvester history
      const theharvesterHistoryData = await getTheHarvesterScans(assessmentId);
      setTheharvesterHistory(theharvesterHistoryData);

      // If we already have theHarvester scans, select the latest one as active
      if (theharvesterHistoryData.length > 0) {
        setSelectedTheharvesterScan(theharvesterHistoryData[0]);
      }

      // 10. Fetch Shodan Status
      const shodanStatusData = await getShodanStatus();
      setShodanStatus(shodanStatusData);

      // 11. Fetch Shodan history
      const shodanHistoryData = await getShodanScans(assessmentId);
      setShodanHistory(shodanHistoryData);

      // If we already have Shodan scans, select the latest one as active
      if (shodanHistoryData.length > 0) {
        setSelectedShodanScan(shodanHistoryData[0]);
      }
    } catch (err) {
      if (!err.response) {
        setError('Backend connection unavailable. Please make sure the Cyber Monkey API is running.');
      } else {
        setError('Unable to load reconnaissance workspace.');
      }
    } finally {
      setLoading(false);
    }
  }, [assessmentId]);

  useEffect(() => {
    if (assessmentId) {
      loadData();
    }
  }, [assessmentId, loadData]);

  const handleStartScan = async () => {
    if (!selectedTargetId) {
      setScanError('Please select a target.');
      return;
    }

    try {
      setScanLoading(true);
      setScanError('');
      
      // Execute scan request (Synchronous Nmap execution)
      const data = await startNmapScan(assessmentId, selectedTargetId, selectedScanProfile);
      
      // Refresh scan history to show the latest result
      const historyData = await getNmapScans(assessmentId);
      setScansHistory(historyData);
      
      // Select the completed scan to render results
      const newScan = historyData.find(s => s.id === data.id);
      setSelectedScan(newScan || data);

      if (data.status === 'failed') {
        setScanError(`Scan failed: ${data.error_output}`);
      }
    } catch (err) {
      if (err.response && err.response.data && err.response.data.detail) {
        setScanError(err.response.data.detail);
      } else if (!err.response) {
        setScanError('Backend connection unavailable. Unable to complete scan execution.');
      } else {
        setScanError('An error occurred during scan execution.');
      }
    } finally {
      setScanLoading(false);
    }
  };

  const handleStartSubfinderScan = async () => {
    if (!selectedSubfinderTargetId) {
      setSubfinderScanError('Please select a target.');
      return;
    }

    try {
      setSubfinderScanLoading(true);
      setSubfinderScanError('');
      
      const data = await startSubfinderScan(assessmentId, selectedSubfinderTargetId);
      
      const historyData = await getSubfinderScans(assessmentId);
      setSubfinderHistory(historyData);
      
      const newScan = historyData.find(s => s.id === data.id);
      setSelectedSubfinderScan(newScan || data);

      if (data.status === 'failed') {
        setSubfinderScanError(`Subdomain enumeration failed: ${data.error_output}`);
      }
    } catch (err) {
      if (err.response && err.response.data && err.response.data.detail) {
        setSubfinderScanError(err.response.data.detail);
      } else if (!err.response) {
        setSubfinderScanError('Backend connection unavailable. Unable to complete subdomain enumeration.');
      } else {
        setSubfinderScanError('An error occurred during subdomain enumeration.');
      }
    } finally {
      setSubfinderScanLoading(false);
    }
  };

  const handleStartDnsScan = async () => {
    if (!selectedDnsTargetId) {
      setDnsScanError('Please select a target.');
      return;
    }

    try {
      setDnsScanLoading(true);
      setDnsScanError('');
      
      const data = await startDnsScan(assessmentId, selectedDnsTargetId);
      
      const historyData = await getDnsScans(assessmentId);
      setDnsHistory(historyData);
      
      const newScan = historyData.find(s => s.id === data.id);
      setSelectedDnsScan(newScan || data);

      if (data.status === 'failed') {
        setDnsScanError(`DNS enumeration failed: ${data.error_output}`);
      }
    } catch (err) {
      if (err.response && err.response.data && err.response.data.detail) {
        setDnsScanError(err.response.data.detail);
      } else if (!err.response) {
        setDnsScanError('Backend connection unavailable. Unable to complete DNS enumeration.');
      } else {
        setDnsScanError('An error occurred during DNS enumeration.');
      }
    } finally {
      setDnsScanLoading(false);
    }
  };

  const handleStartTheHarvesterScan = async () => {
    if (!selectedTheharvesterTargetId) {
      setTheharvesterScanError('Please select a target.');
      return;
    }

    try {
      setTheharvesterScanLoading(true);
      setTheharvesterScanError('');
      
      const data = await startTheHarvesterScan(assessmentId, selectedTheharvesterTargetId);
      
      const historyData = await getTheHarvesterScans(assessmentId);
      setTheharvesterHistory(historyData);
      
      const newScan = historyData.find(s => s.id === data.id);
      setSelectedTheharvesterScan(newScan || data);

      if (data.status === 'failed') {
        setTheharvesterScanError(`theHarvester OSINT scan failed: ${data.error_output}`);
      }
    } catch (err) {
      if (err.response && err.response.data && err.response.data.detail) {
        setTheharvesterScanError(err.response.data.detail);
      } else if (!err.response) {
        setTheharvesterScanError('Backend connection unavailable. Unable to complete OSINT scan.');
      } else {
        setTheharvesterScanError('An error occurred during OSINT scan.');
      }
    } finally {
      setTheharvesterScanLoading(false);
    }
  };

  const handleStartShodanScan = async () => {
    if (!selectedShodanTargetId) {
      setShodanScanError('Please select a target.');
      return;
    }

    try {
      setShodanScanLoading(true);
      setShodanScanError('');

      // Invoke Shodan API
      const data = await startShodanScan(assessmentId, selectedShodanTargetId);

      // Refresh Shodan history
      const historyData = await getShodanScans(assessmentId);
      setShodanHistory(historyData);

      // Select the new scan
      const newScan = historyData.find(s => s.id === data.id);
      setSelectedShodanScan(newScan || data);

      if (data.status === 'failed') {
        setShodanScanError(`Shodan query failed: ${data.error_output}`);
      }
    } catch (err) {
      if (err.response && err.response.data && err.response.data.detail) {
        setShodanScanError(err.response.data.detail);
      } else if (!err.response) {
        setShodanScanError('Backend connection unavailable. Unable to complete Shodan query.');
      } else {
        setShodanScanError('An error occurred during Shodan query.');
      }
    } finally {
      setShodanScanLoading(false);
    }
  };

  const getScanStatusBadge = (status) => {
    const s = String(status || '').toUpperCase();
    switch (s) {
      case 'RUNNING':
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
            RUNNING
          </span>
        );
      case 'COMPLETED':
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-teal-500/10 text-teal-300 border border-teal-500/20">
            COMPLETED
          </span>
        );
      case 'FAILED':
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
            FAILED
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-slate-500/10 text-slate-300 border border-slate-500/20">
            {s}
          </span>
        );
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-slate-100">
        <svg className="animate-spin h-8 w-8 text-teal-400 mb-4" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        <p className="text-slate-400 text-sm font-semibold">Configuring scanner session parameters...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 text-center border border-rose-500/20 bg-rose-500/5 rounded-2xl">
        <div className="text-3xl mb-3">⚠️</div>
        <h4 className="text-lg font-bold text-rose-400 mb-2">Reconnaissance Workspace Error</h4>
        <p className="text-slate-400 text-sm mb-4">{error}</p>
        <button 
          onClick={loadData}
          className="px-4 py-2 bg-white/5 border border-white/10 hover:bg-white/10 rounded-lg text-slate-200 text-sm transition-colors cursor-pointer"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      
      {/* Title block */}
      <div>
        <h1 className="text-3xl font-black mb-1">Reconnaissance</h1>
        <p className="text-slate-400 text-sm">
          Perform authorized information gathering against assessment targets.
        </p>
      </div>

      {/* Nmap Engine availability status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-xl bg-white/5 border border-white/5 gap-3">
        <div className="text-left">
          <span className="block text-xs font-bold text-slate-500 uppercase tracking-wider">
            Detected Scan Utility
          </span>
          <span className="font-mono text-sm text-slate-300">
            {nmapStatus.installed ? (nmapStatus.version || 'Nmap Network Scanner') : 'None'}
          </span>
        </div>
        <div>
          {nmapStatus.installed ? (
            <span className="inline-flex items-center gap-1.5 text-teal-400 font-bold text-xs bg-teal-500/10 px-3 py-1 rounded border border-teal-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse"></span>
              Nmap Ready
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-rose-400 font-bold text-xs bg-rose-500/10 px-3 py-1 rounded border border-rose-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
              Nmap Not Installed
            </span>
          )}
        </div>
      </div>

      {!nmapStatus.installed && (
        <div className="p-4 bg-orange-500/10 border border-orange-500/20 text-orange-300 text-sm rounded-xl text-left">
          <strong>Nmap is not installed on the backend.</strong> Scanning capabilities are disabled.
          To set up Nmap on the developer's backend machine, check the documentation.
        </div>
      )}

      {/* Workspace configurations layout grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Target scoping checklist card */}
        <div className="p-6 rounded-2xl cyber-glass space-y-4 text-left border border-white/5">
          <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase">
            Assessment Targets Scoping
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Click on any authorized target to auto-select it in the scanner configuration.
          </p>
          <div className="space-y-3 max-h-[350px] overflow-y-auto pr-1">
            {targets.length === 0 ? (
              <p className="text-slate-500 text-xs">No targets configured for this assessment.</p>
            ) : (
              targets.map((t) => {
                const isEligible = t.scope_status === 'in_scope' && t.authorization_confirmed;
                const isSelected = selectedTargetId === t.id;
                return (
                  <div
                    key={t.id}
                    onClick={() => {
                      if (isEligible) {
                        setSelectedTargetId(t.id);
                        if (t.target_type === 'Domain') {
                          setSelectedSubfinderTargetId(t.id);
                          setSelectedDnsTargetId(t.id);
                        }
                      }
                    }}
                    className={`p-3.5 rounded-xl border transition-all ${
                      isEligible
                        ? 'cursor-pointer hover:border-teal-500/40 bg-white/5'
                        : 'opacity-50 cursor-not-allowed bg-black/20 border-dashed border-white/10'
                    } ${
                      isSelected
                        ? 'border-teal-400 bg-teal-500/5 shadow-[0_0_15px_rgba(20,184,166,0.05)]'
                        : 'border-white/5'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-mono text-sm font-bold text-slate-100 break-all">
                        {t.target_value}
                      </span>
                      <span className="px-2 py-0.5 text-[9px] font-medium rounded bg-white/5 text-slate-400 border border-white/10">
                        {t.target_type}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      {t.scope_status === 'in_scope' ? (
                        <span className="px-2 py-0.5 text-[9px] font-bold rounded bg-teal-500/10 text-teal-300 border border-teal-500/20">
                          IN SCOPE
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 text-[9px] font-bold rounded bg-rose-500/10 text-rose-300 border border-rose-500/20">
                          OUT OF SCOPE
                        </span>
                      )}
                      {t.authorization_confirmed ? (
                        <span className="px-2 py-0.5 text-[9px] font-bold rounded bg-teal-500/10 text-teal-300 border border-teal-500/20">
                          AUTHORIZED
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 text-[9px] font-bold rounded bg-rose-500/10 text-rose-300 border border-rose-500/20">
                          UNAUTHORIZED
                        </span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Nmap Scan configuration parameters panel card */}
        <div className="p-6 rounded-2xl cyber-glass space-y-4 text-left border border-white/5 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4">
              Nmap Network & Service Enumeration
            </h3>
            
            {scanError && (
              <div className="p-3.5 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs rounded-xl mb-4 leading-relaxed whitespace-pre-wrap">
                <strong>Scanner Error:</strong> {scanError}
              </div>
            )}

            <div className="space-y-4">
              {/* Target selection dropdown */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Target
                </label>
                <select
                  value={selectedTargetId}
                  onChange={(e) => setSelectedTargetId(e.target.value)}
                  disabled={scanLoading || !nmapStatus.installed}
                  className="w-full px-4 py-2.5 rounded-lg bg-[#0F111E] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer text-sm"
                >
                  <option value="">-- Select Authorized Target --</option>
                  {targets
                    .filter((t) => t.scope_status === 'in_scope' && t.authorization_confirmed)
                    .map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.target_value} ({t.target_type})
                      </option>
                    ))}
                </select>
              </div>

              {/* Preset scan configurations profile dropdown */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Scan Type
                </label>
                <select
                  value={selectedScanProfile}
                  onChange={(e) => setSelectedScanProfile(e.target.value)}
                  disabled={scanLoading || !nmapStatus.installed}
                  className="w-full px-4 py-2.5 rounded-lg bg-[#0F111E] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer text-sm"
                >
                  <option value="host_discovery">Host Discovery (-sn)</option>
                  <option value="basic_port">Basic Port Scan (-F)</option>
                  <option value="service_detection">Service Detection (-sV)</option>
                  <option value="comprehensive">Comprehensive Enumeration (-sV -sC)</option>
                </select>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-white/5">
            <button
              onClick={handleStartScan}
              disabled={scanLoading || !selectedTargetId || !nmapStatus.installed}
              className="w-full py-3 rounded-lg bg-teal-400 hover:bg-teal-300 disabled:opacity-40 disabled:hover:bg-teal-400 text-[#090A0F] font-bold text-sm shadow-lg shadow-teal-500/10 cursor-pointer flex items-center justify-center gap-2 transition-all duration-300"
            >
              {scanLoading ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-[#090A0F]" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Scanning Target (real-time)...
                </>
              ) : (
                'Start Scan'
              )}
            </button>
          </div>
        </div>

      </div>

      {/* Selected Scan Results View Component */}
      {selectedScan && (
        <div className="space-y-6">
          
          {/* Scan summary metrics details */}
          <div className="p-6 rounded-2xl cyber-glass text-left relative overflow-hidden border border-white/5">
            <div className="absolute top-0 left-0 w-1.5 h-full bg-teal-400"></div>
            <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
              Scan Results
            </h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6 text-sm mb-2">
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Target</span>
                <span className="font-mono font-bold text-slate-200">{selectedScan.target?.target_value || '—'}</span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Scan Type</span>
                <span className="font-semibold text-slate-200 capitalize">
                  {String(selectedScan.scan_profile || '').replace('_', ' ')}
                </span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Status</span>
                <div className="mt-1">{getScanStatusBadge(selectedScan.status)}</div>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Start Time</span>
                <span className="font-mono text-slate-300 text-xs">
                  {selectedScan.started_at ? new Date(selectedScan.started_at).toLocaleString('en-GB') : '—'}
                </span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Completion Time</span>
                <span className="font-mono text-slate-300 text-xs">
                  {selectedScan.completed_at ? new Date(selectedScan.completed_at).toLocaleString('en-GB') : '—'}
                </span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Duration</span>
                <span className="font-mono text-slate-300 text-xs">
                  {selectedScan.duration ? `${selectedScan.duration} seconds` : '—'}
                </span>
              </div>
            </div>
          </div>

          {/* Discovered Services port/service info table list */}
          <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5">
            <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
              Discovered Services
            </h3>
            {selectedScan.status === 'completed' ? (
              selectedScan.ports && selectedScan.ports.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm border-collapse">
                    <thead>
                      <tr className="border-b border-white/10 text-slate-400 text-xs uppercase tracking-wider">
                        <th className="py-3 px-4">Port</th>
                        <th className="py-3 px-4">Protocol</th>
                        <th className="py-3 px-4">State</th>
                        <th className="py-3 px-4">Service</th>
                        <th className="py-3 px-4">Version</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono">
                      {selectedScan.ports.map((port) => (
                        <tr key={port.id} className="hover:bg-white/5 transition-colors">
                          <td className="py-3 px-4 text-teal-400 font-bold">{port.port}</td>
                          <td className="py-3 px-4 uppercase text-slate-300">{port.protocol}</td>
                          <td className="py-3 px-4">
                            <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-teal-500/10 text-teal-400 border border-teal-500/20">
                              {port.state.toUpperCase()}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-slate-200">{port.service || '—'}</td>
                          <td className="py-3 px-4 text-slate-400 font-sans text-xs">{port.version || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-slate-500 text-xs py-4">No open ports discovered on this target.</p>
              )
            ) : selectedScan.status === 'failed' ? (
              <div className="p-4 bg-rose-500/5 rounded-xl border border-rose-500/10 text-rose-300 text-xs font-mono leading-relaxed">
                <strong>Scan Failure Description:</strong> {selectedScan.error_output || 'An internal scanner process error occurred.'}
              </div>
            ) : (
              <p className="text-slate-500 text-xs py-4">Scanner is currently processing target...</p>
            )}
          </div>

          {/* Raw Output collapsible segment container */}
          <CollapsibleSection title="Raw Nmap Output" defaultOpen={false}>
            <div className="space-y-4">
              {selectedScan.raw_output ? (
                <pre className="font-mono text-xs bg-black/40 border border-white/10 p-4 rounded-xl text-slate-300 overflow-x-auto whitespace-pre-wrap text-left leading-relaxed">
                  {selectedScan.raw_output}
                </pre>
              ) : (
                <p className="text-slate-500 text-xs py-2 text-left">No raw console stdout captured.</p>
              )}
              {selectedScan.error_output && selectedScan.status === 'failed' && (
                <div className="text-left border-t border-white/5 pt-4">
                  <span className="block text-xs font-bold text-rose-400 uppercase mb-2">Error Stream / Stderr:</span>
                  <pre className="font-mono text-xs bg-rose-950/15 border border-rose-900/30 p-4 rounded-xl text-rose-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                    {selectedScan.error_output}
                  </pre>
                </div>
              )}
            </div>
          </CollapsibleSection>

        </div>
      )}

      {/* Scanned targets execution history card list */}
      <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5">
        <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
          Scan History
        </h3>
        {scansHistory.length === 0 ? (
          <p className="text-slate-500 text-xs">No scan history recorded for this assessment.</p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {scansHistory.map((scan) => {
              const isCurrent = selectedScan?.id === scan.id;
              return (
                <div
                  key={scan.id}
                  onClick={() => setSelectedScan(scan)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer bg-white/5 hover:border-teal-500/30 ${
                    isCurrent ? 'border-teal-400 bg-teal-500/5 shadow-[0_0_15px_rgba(20,184,166,0.05)]' : 'border-white/5'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <span className="font-mono text-sm font-bold text-slate-100 truncate">
                      {scan.target?.target_value || '—'}
                    </span>
                    <div className="shrink-0">{getScanStatusBadge(scan.status)}</div>
                  </div>
                  <div className="text-xs text-slate-400 capitalize mb-3">
                    {String(scan.scan_profile || '').replace('_', ' ')}
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-semibold tracking-wide">
                    <span>
                      {scan.started_at ? new Date(scan.started_at).toLocaleDateString('en-GB', {
                        day: '2-digit',
                        month: 'short',
                        year: 'numeric'
                      }) : '—'}
                    </span>
                    <span>{scan.duration ? `${scan.duration}s` : '—'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ======================================================== */}
      {/* Subdomain Enumeration (Subfinder) Section */}
      {/* ======================================================== */}
      <div className="pt-6 border-t border-white/5 mt-10">
        <h2 className="text-2xl font-black mb-1">Subdomain Enumeration</h2>
        <p className="text-slate-400 text-sm">
          Perform authorized passive subdomain discovery using Subfinder.
        </p>
      </div>

      {/* Subfinder availability status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-xl bg-white/5 border border-white/5 gap-3 mt-4">
        <div className="text-left">
          <span className="block text-xs font-bold text-slate-500 uppercase tracking-wider">
            Detected Subdomain Discovery Utility
          </span>
          <span className="font-mono text-sm text-slate-300">
            {subfinderStatus.installed ? (subfinderStatus.version || 'Subfinder') : 'None'}
          </span>
        </div>
        <div>
          {subfinderStatus.installed ? (
            <span className="inline-flex items-center gap-1.5 text-teal-400 font-bold text-xs bg-teal-500/10 px-3 py-1 rounded border border-teal-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse"></span>
              🟢 Subfinder Ready
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-rose-400 font-bold text-xs bg-rose-500/10 px-3 py-1 rounded border border-rose-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
              🔴 Subfinder Not Installed
            </span>
          )}
        </div>
      </div>

      {!subfinderStatus.installed && (
        <div className="p-4 bg-orange-500/10 border border-orange-500/20 text-orange-300 text-sm rounded-xl text-left mt-3">
          <strong>Subfinder is not installed on the backend.</strong> Subdomain enumeration capabilities are disabled.
          To set up Subfinder on the developer's backend machine, check the documentation.
        </div>
      )}

      {/* Subdomain selector and scanner configurations */}
      <div className="grid grid-cols-1 gap-6 mt-6">
        <div className="p-6 rounded-2xl cyber-glass space-y-4 text-left border border-white/5">
          <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase">
            Subfinder Configuration
          </h3>
          
          {subfinderScanError && (
            <div className="p-3.5 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs rounded-xl mb-4 leading-relaxed whitespace-pre-wrap">
              <strong>Scanner Error:</strong> {subfinderScanError}
            </div>
          )}

          <div className="space-y-4">
            {/* Target selector dropdown */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Authorized Domain Target
              </label>
              <select
                value={selectedSubfinderTargetId}
                onChange={(e) => setSelectedSubfinderTargetId(e.target.value)}
                disabled={subfinderScanLoading || !subfinderStatus.installed}
                className="w-full px-4 py-2.5 rounded-lg bg-[#0F111E] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer text-sm"
              >
                <option value="">-- Select Authorized Domain Target --</option>
                {targets
                  .filter((t) => t.target_type === 'Domain' && t.scope_status === 'in_scope' && t.authorization_confirmed)
                  .map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.target_value}
                    </option>
                  ))}
              </select>
            </div>

            <button
              onClick={handleStartSubfinderScan}
              disabled={subfinderScanLoading || !selectedSubfinderTargetId || !subfinderStatus.installed}
              className="w-full py-3 rounded-lg bg-teal-400 hover:bg-teal-300 disabled:opacity-40 disabled:hover:bg-teal-400 text-[#090A0F] font-bold text-sm shadow-lg shadow-teal-500/10 cursor-pointer flex items-center justify-center gap-2 transition-all duration-300"
            >
              {subfinderScanLoading ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-[#090A0F]" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Enumerating...
                </>
              ) : (
                'Enumerate Subdomains'
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Selected Subfinder scan results view */}
      {selectedSubfinderScan && (
        <div className="space-y-6 mt-6">
          
          {/* Scan summary metrics details */}
          <div className="p-6 rounded-2xl cyber-glass text-left relative overflow-hidden border border-white/5">
            <div className="absolute top-0 left-0 w-1.5 h-full bg-teal-400"></div>
            <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
              Enumeration Results
            </h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6 text-sm mb-2">
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Target</span>
                <span className="font-mono font-bold text-slate-200">{selectedSubfinderScan.target?.target_value || '—'}</span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Status</span>
                <div className="mt-1">{getScanStatusBadge(selectedSubfinderScan.status)}</div>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Duration</span>
                <span className="font-mono text-slate-300 text-xs">
                  {selectedSubfinderScan.duration ? `${selectedSubfinderScan.duration} seconds` : '—'}
                </span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Start Time</span>
                <span className="font-mono text-slate-300 text-xs">
                  {selectedSubfinderScan.started_at ? new Date(selectedSubfinderScan.started_at).toLocaleString('en-GB') : '—'}
                </span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Subdomains Found</span>
                <span className="font-mono text-teal-400 font-bold">{selectedSubfinderScan.subdomains?.length || 0}</span>
              </div>
            </div>
          </div>

          {/* Discovered Subdomains List */}
          <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5">
            <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
              Discovered Subdomains
            </h3>
            {selectedSubfinderScan.status === 'completed' ? (
              selectedSubfinderScan.subdomains && selectedSubfinderScan.subdomains.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm border-collapse">
                    <thead>
                      <tr className="border-b border-white/10 text-slate-400 text-xs uppercase tracking-wider">
                        <th className="py-3 px-4">Subdomain</th>
                        <th className="py-3 px-4">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono">
                      {selectedSubfinderScan.subdomains.map((sub) => (
                        <tr key={sub.id} className="hover:bg-white/5 transition-colors">
                          <td className="py-3 px-4 text-teal-400">{sub.subdomain}</td>
                          <td className="py-3 px-4">
                            <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-teal-500/10 text-teal-400 border border-teal-500/20">
                              Discovered
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-slate-500 text-xs py-4">No subdomains discovered on this target.</p>
              )
            ) : selectedSubfinderScan.status === 'failed' ? (
              <div className="p-4 bg-rose-500/5 rounded-xl border border-rose-500/10 text-rose-300 text-xs font-mono leading-relaxed">
                <strong>Scan Failure Description:</strong> {selectedSubfinderScan.error_output || 'An internal scanner process error occurred.'}
              </div>
            ) : (
              <p className="text-slate-500 text-xs py-4">Scanner is currently processing target...</p>
            )}
          </div>

          {/* Raw Output collapsible container */}
          <CollapsibleSection title="Raw Subfinder Output" defaultOpen={false}>
            <div className="space-y-4">
              {selectedSubfinderScan.raw_output ? (
                <pre className="font-mono text-xs bg-black/40 border border-white/10 p-4 rounded-xl text-slate-300 overflow-x-auto whitespace-pre-wrap text-left leading-relaxed">
                  {selectedSubfinderScan.raw_output}
                </pre>
              ) : (
                <p className="text-slate-500 text-xs py-2 text-left">No raw console stdout captured.</p>
              )}
              {selectedSubfinderScan.error_output && selectedSubfinderScan.status === 'failed' && (
                <div className="text-left border-t border-white/5 pt-4">
                  <span className="block text-xs font-bold text-rose-400 uppercase mb-2">Error Stream / Stderr:</span>
                  <pre className="font-mono text-xs bg-rose-950/15 border border-rose-900/30 p-4 rounded-xl text-rose-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                    {selectedSubfinderScan.error_output}
                  </pre>
                </div>
              )}
            </div>
          </CollapsibleSection>

        </div>
      )}

      {/* Subdomain enumeration history list */}
      <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5 mt-6">
        <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
          Subdomain Enumeration History
        </h3>
        {subfinderHistory.length === 0 ? (
          <p className="text-slate-500 text-xs">No subdomain enumeration history recorded for this assessment.</p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {subfinderHistory.map((scan) => {
              const isCurrent = selectedSubfinderScan?.id === scan.id;
              return (
                <div
                  key={scan.id}
                  onClick={() => setSelectedSubfinderScan(scan)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer bg-white/5 hover:border-teal-500/30 ${
                    isCurrent ? 'border-teal-400 bg-teal-500/5 shadow-[0_0_15px_rgba(20,184,166,0.05)]' : 'border-white/5'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <span className="font-mono text-sm font-bold text-slate-100 truncate">
                      {scan.target?.target_value || '—'}
                    </span>
                    <div className="shrink-0">{getScanStatusBadge(scan.status)}</div>
                  </div>
                  <div className="text-xs text-slate-400 mb-3">
                    Subdomains Found: <span className="text-teal-400 font-bold">{scan.subdomains?.length || 0}</span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-semibold tracking-wide">
                    <span>
                      {scan.started_at ? new Date(scan.started_at).toLocaleDateString('en-GB', {
                        day: '2-digit',
                        month: 'short',
                        year: 'numeric'
                      }) : '—'}
                    </span>
                    <span>{scan.duration ? `${scan.duration}s` : '—'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ======================================================== */}
      {/* DNS Enumeration Section */}
      {/* ======================================================== */}
      <div className="pt-6 border-t border-white/5 mt-10">
        <h2 className="text-2xl font-black mb-1">DNS Enumeration</h2>
        <p className="text-slate-400 text-sm">
          Perform authorized DNS record enumeration for domain targets.
        </p>
      </div>

      {/* DNS Resolver Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-xl bg-white/5 border border-white/5 gap-3 mt-4">
        <div className="text-left">
          <span className="block text-xs font-bold text-slate-500 uppercase tracking-wider">
            DNS Resolver Status
          </span>
          <span className="font-mono text-sm text-slate-300">
            {dnsStatus.available ? `Available (Resolver: ${dnsStatus.resolver})` : `Unavailable (${dnsStatus.resolver || 'No resolver configured'})`}
          </span>
        </div>
        <div>
          {dnsStatus.available ? (
            <span className="inline-flex items-center gap-1.5 text-teal-400 font-bold text-xs bg-teal-500/10 px-3 py-1 rounded border border-teal-500/20">
              🟢 Resolver Ready
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-rose-400 font-bold text-xs bg-rose-500/10 px-3 py-1 rounded border border-rose-500/20">
              🔴 Resolver Unavailable
            </span>
          )}
        </div>
      </div>

      {/* DNS Configuration panel */}
      <div className="grid grid-cols-1 gap-6 mt-6">
        <div className="p-6 rounded-2xl cyber-glass space-y-4 text-left border border-white/5">
          <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase">
            DNS Configuration
          </h3>
          
          {dnsScanError && (
            <div className="p-3.5 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs rounded-xl mb-4 leading-relaxed whitespace-pre-wrap">
              <strong>Scanner Error:</strong> {dnsScanError}
            </div>
          )}

          <div className="space-y-4">
            {/* Target selector dropdown */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Target
              </label>
              <select
                value={selectedDnsTargetId}
                onChange={(e) => setSelectedDnsTargetId(e.target.value)}
                disabled={dnsScanLoading || !dnsStatus.available}
                className="w-full px-4 py-2.5 rounded-lg bg-[#0F111E] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer text-sm"
              >
                <option value="">-- Select Authorized Domain Target --</option>
                {targets
                  .filter((t) => t.target_type === 'Domain' && t.scope_status === 'in_scope' && t.authorization_confirmed)
                  .map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.target_value}
                    </option>
                  ))}
              </select>
            </div>

            <button
              onClick={handleStartDnsScan}
              disabled={dnsScanLoading || !selectedDnsTargetId || !dnsStatus.available}
              className="w-full py-3 rounded-lg bg-teal-400 hover:bg-teal-300 disabled:opacity-40 disabled:hover:bg-teal-400 text-[#090A0F] font-bold text-sm shadow-lg shadow-teal-500/10 cursor-pointer flex items-center justify-center gap-2 transition-all duration-300"
            >
              {dnsScanLoading ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-[#090A0F]" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Enumerating DNS Records...
                </>
              ) : (
                'Enumerate DNS Records'
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Selected DNS scan results view */}
      {selectedDnsScan && (
        <div className="space-y-6 mt-6">
          
          {/* Scan summary metrics details */}
          <div className="p-6 rounded-2xl cyber-glass text-left relative overflow-hidden border border-white/5">
            <div className="absolute top-0 left-0 w-1.5 h-full bg-teal-400"></div>
            <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
              DNS Enumeration Results
            </h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6 text-sm mb-2">
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Target</span>
                <span className="font-mono font-bold text-slate-200">{selectedDnsScan.target?.target_value || '—'}</span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Status</span>
                <div className="mt-1">{getScanStatusBadge(selectedDnsScan.status)}</div>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Duration</span>
                <span className="font-mono text-slate-300 text-xs">
                  {selectedDnsScan.duration ? `${selectedDnsScan.duration} seconds` : '—'}
                </span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Start Time</span>
                <span className="font-mono text-slate-300 text-xs">
                  {selectedDnsScan.started_at ? new Date(selectedDnsScan.started_at).toLocaleString('en-GB') : '—'}
                </span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Records Found</span>
                <span className="font-mono text-teal-400 font-bold">{selectedDnsScan.records?.length || 0}</span>
              </div>
            </div>
          </div>

          {/* DNS Records Table */}
          <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5">
            <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
              DNS Records
            </h3>
            {selectedDnsScan.status === 'completed' ? (
              selectedDnsScan.records && selectedDnsScan.records.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm border-collapse">
                    <thead>
                      <tr className="border-b border-white/10 text-slate-400 text-xs uppercase tracking-wider">
                        <th className="py-3 px-4">TYPE</th>
                        <th className="py-3 px-4">NAME</th>
                        <th className="py-3 px-4">VALUE</th>
                        <th className="py-3 px-4">TTL</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono">
                      {selectedDnsScan.records.map((rec) => (
                        <tr key={rec.id} className="hover:bg-white/5 transition-colors">
                          <td className="py-3 px-4 text-teal-400 font-bold">{rec.record_type}</td>
                          <td className="py-3 px-4 text-slate-300">{rec.name}</td>
                          <td className="py-3 px-4 text-slate-200 break-all">{rec.value}</td>
                          <td className="py-3 px-4 text-slate-400 font-sans text-xs">{rec.ttl}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-slate-500 text-xs py-4">No DNS records discovered on this target.</p>
              )
            ) : selectedDnsScan.status === 'failed' ? (
              <div className="p-4 bg-rose-500/5 rounded-xl border border-rose-500/10 text-rose-300 text-xs font-mono leading-relaxed">
                <strong>Scan Failure Description:</strong> {selectedDnsScan.error_output || 'An internal scanner process error occurred.'}
              </div>
            ) : (
              <p className="text-slate-500 text-xs py-4">Scanner is currently processing target...</p>
            )}
          </div>

        </div>
      )}

      {/* DNS history list */}
      <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5 mt-6">
        <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
          DNS Enumeration History
        </h3>
        {dnsHistory.length === 0 ? (
          <p className="text-slate-500 text-xs">No DNS enumeration history recorded for this assessment.</p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {dnsHistory.map((scan) => {
              const isCurrent = selectedDnsScan?.id === scan.id;
              return (
                <div
                  key={scan.id}
                  onClick={() => setSelectedDnsScan(scan)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer bg-white/5 hover:border-teal-500/30 ${
                    isCurrent ? 'border-teal-400 bg-teal-500/5 shadow-[0_0_15px_rgba(20,184,166,0.05)]' : 'border-white/5'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <span className="font-mono text-sm font-bold text-slate-100 truncate">
                      {scan.target?.target_value || '—'}
                    </span>
                    <div className="shrink-0">{getScanStatusBadge(scan.status)}</div>
                  </div>
                  <div className="text-xs text-slate-400 mb-3">
                    Records Found: <span className="text-teal-400 font-bold">{scan.records?.length || 0}</span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-semibold tracking-wide">
                    <span>
                      {scan.started_at ? new Date(scan.started_at).toLocaleDateString('en-GB', {
                        day: '2-digit',
                        month: 'short',
                        year: 'numeric'
                      }) : '—'}
                    </span>
                    <span>{scan.duration ? `${scan.duration}s` : '—'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ======================================================== */}
      {/* Public OSINT Enumeration (theHarvester) Section */}
      {/* ======================================================== */}
      <div className="pt-6 border-t border-white/5 mt-10">
        <h2 className="text-2xl font-black mb-1">Public OSINT Enumeration</h2>
        <p className="text-slate-400 text-sm">
          Run the real theHarvester tool against an authorized domain and collect publicly available reconnaissance information.
        </p>
      </div>

      {/* theHarvester availability status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-xl bg-white/5 border border-white/5 gap-3 mt-4">
        <div className="text-left">
          <span className="block text-xs font-bold text-slate-500 uppercase tracking-wider">
            Detected Public OSINT Utility
          </span>
          <span className="font-mono text-sm text-slate-300">
            {theharvesterStatus.available ? (theharvesterStatus.version || 'theHarvester') : 'None'}
          </span>
        </div>
        <div>
          {theharvesterStatus.available ? (
            <span className="inline-flex items-center gap-1.5 text-teal-400 font-bold text-xs bg-teal-500/10 px-3 py-1 rounded border border-teal-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse"></span>
              🟢 theHarvester Ready
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-rose-400 font-bold text-xs bg-rose-500/10 px-3 py-1 rounded border border-rose-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
              🔴 theHarvester Unavailable
            </span>
          )}
        </div>
      </div>

      {!theharvesterStatus.available && (
        <div className="p-4 bg-orange-500/10 border border-orange-500/20 text-orange-300 text-sm rounded-xl text-left mt-3">
          <strong>theHarvester is not available on the backend.</strong> OSINT enumeration capabilities are disabled.
          Verify the path <code>{theharvesterStatus.path || 'C:\\Tools\\theHarvester'}</code> exists and is configured correctly.
        </div>
      )}

      {/* theHarvester selector and configurations */}
      <div className="grid grid-cols-1 gap-6 mt-6">
        <div className="p-6 rounded-2xl cyber-glass space-y-4 text-left border border-white/5">
          <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase">
            theHarvester Configuration
          </h3>
          
          {theharvesterScanError && (
            <div className="p-3.5 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs rounded-xl mb-4 leading-relaxed whitespace-pre-wrap">
              <strong>Scanner Error:</strong> {theharvesterScanError}
            </div>
          )}

          <div className="space-y-4">
            {/* Target selector dropdown */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Authorized Domain Target
              </label>
              <select
                value={selectedTheharvesterTargetId}
                onChange={(e) => setSelectedTheharvesterTargetId(e.target.value)}
                disabled={theharvesterScanLoading || !theharvesterStatus.available}
                className="w-full px-4 py-2.5 rounded-lg bg-[#0F111E] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer text-sm"
              >
                <option value="">-- Select Authorized Domain Target --</option>
                {targets
                  .filter((t) => t.target_type === 'Domain' && t.scope_status === 'in_scope' && t.authorization_confirmed)
                  .map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.target_value}
                    </option>
                  ))}
              </select>
            </div>

            <button
              onClick={handleStartTheHarvesterScan}
              disabled={theharvesterScanLoading || !selectedTheharvesterTargetId || !theharvesterStatus.available}
              className="w-full py-3 rounded-lg bg-teal-400 hover:bg-teal-300 disabled:opacity-40 disabled:hover:bg-teal-400 text-[#090A0F] font-bold text-sm shadow-lg shadow-teal-500/10 cursor-pointer flex items-center justify-center gap-2 transition-all duration-300"
            >
              {theharvesterScanLoading ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-[#090A0F]" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Running Public OSINT Enumeration...
                </>
              ) : (
                'Run Public OSINT Enumeration'
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Selected theHarvester scan results view */}
      {selectedTheharvesterScan && (
        <div className="space-y-6 mt-6">
          
          {/* Scan summary metrics details */}
          <div className="p-6 rounded-2xl cyber-glass text-left relative overflow-hidden border border-white/5">
            <div className="absolute top-0 left-0 w-1.5 h-full bg-teal-400"></div>
            <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
              Public OSINT Results
            </h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-6 text-sm mb-4">
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Target</span>
                <span className="font-mono font-bold text-slate-200">{selectedTheharvesterScan.target?.target_value || '—'}</span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Status</span>
                <div className="mt-1">{getScanStatusBadge(selectedTheharvesterScan.status)}</div>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Duration</span>
                <span className="font-mono text-slate-300 text-xs">
                  {selectedTheharvesterScan.duration ? `${selectedTheharvesterScan.duration} seconds` : '—'}
                </span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Start Time</span>
                <span className="font-mono text-slate-300 text-xs">
                  {selectedTheharvesterScan.started_at ? new Date(selectedTheharvesterScan.started_at).toLocaleString('en-GB') : '—'}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4 border-t border-white/5">
              <div className="p-3 bg-white/5 rounded-xl border border-white/5">
                <span className="block text-[10px] text-slate-500 uppercase font-bold mb-1">Emails Found</span>
                <span className="text-xl font-bold font-mono text-teal-400">{selectedTheharvesterScan.emails_found || 0}</span>
              </div>
              <div className="p-3 bg-white/5 rounded-xl border border-white/5">
                <span className="block text-[10px] text-slate-500 uppercase font-bold mb-1">Hosts Found</span>
                <span className="text-xl font-bold font-mono text-teal-400">{selectedTheharvesterScan.hosts_found || 0}</span>
              </div>
              <div className="p-3 bg-white/5 rounded-xl border border-white/5">
                <span className="block text-[10px] text-slate-500 uppercase font-bold mb-1">IPs Found</span>
                <span className="text-xl font-bold font-mono text-teal-400">{selectedTheharvesterScan.ips_found || 0}</span>
              </div>
              <div className="p-3 bg-white/5 rounded-xl border border-white/5">
                <span className="block text-[10px] text-slate-500 uppercase font-bold mb-1">Names Found</span>
                <span className="text-xl font-bold font-mono text-teal-400">{selectedTheharvesterScan.names_found || 0}</span>
              </div>
            </div>
          </div>

          {/* Result Categories Tables */}
          {selectedTheharvesterScan.status === 'completed' ? (
            <div className="space-y-6">
              
              {/* Emails Table */}
              <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5">
                <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
                  Emails
                </h3>
                {selectedTheharvesterScan.emails && selectedTheharvesterScan.emails.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm border-collapse">
                      <thead>
                        <tr className="border-b border-white/10 text-slate-400 text-xs uppercase tracking-wider">
                          <th className="py-3 px-4">Email</th>
                          <th className="py-3 px-4">Source</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5 font-mono">
                        {selectedTheharvesterScan.emails.map((e) => (
                          <tr key={e.id} className="hover:bg-white/5 transition-colors">
                            <td className="py-3 px-4 text-teal-400 break-all">{e.email}</td>
                            <td className="py-3 px-4 text-slate-300">{e.source || 'unknown'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-slate-500 text-xs py-2">No results discovered.</p>
                )}
              </div>

              {/* Hosts Table */}
              <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5">
                <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
                  Hosts
                </h3>
                {selectedTheharvesterScan.hosts && selectedTheharvesterScan.hosts.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm border-collapse">
                      <thead>
                        <tr className="border-b border-white/10 text-slate-400 text-xs uppercase tracking-wider">
                          <th className="py-3 px-4">Hostname</th>
                          <th className="py-3 px-4">IP</th>
                          <th className="py-3 px-4">Source</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5 font-mono">
                        {selectedTheharvesterScan.hosts.map((h) => (
                          <tr key={h.id} className="hover:bg-white/5 transition-colors">
                            <td className="py-3 px-4 text-teal-400 break-all">{h.hostname}</td>
                            <td className="py-3 px-4 text-slate-200">{h.ip || '—'}</td>
                            <td className="py-3 px-4 text-slate-300">{h.source || 'unknown'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-slate-500 text-xs py-2">No results discovered.</p>
                )}
              </div>

              {/* IPs Table */}
              <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5">
                <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
                  IPs
                </h3>
                {selectedTheharvesterScan.ips && selectedTheharvesterScan.ips.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm border-collapse">
                      <thead>
                        <tr className="border-b border-white/10 text-slate-400 text-xs uppercase tracking-wider">
                          <th className="py-3 px-4">IP</th>
                          <th className="py-3 px-4">Source</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5 font-mono">
                        {selectedTheharvesterScan.ips.map((ip) => (
                          <tr key={ip.id} className="hover:bg-white/5 transition-colors">
                            <td className="py-3 px-4 text-teal-400">{ip.ip}</td>
                            <td className="py-3 px-4 text-slate-300">{ip.source || 'unknown'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-slate-500 text-xs py-2">No results discovered.</p>
                )}
              </div>

              {/* Names Table */}
              <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5">
                <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
                  Names
                </h3>
                {selectedTheharvesterScan.names && selectedTheharvesterScan.names.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm border-collapse">
                      <thead>
                        <tr className="border-b border-white/10 text-slate-400 text-xs uppercase tracking-wider">
                          <th className="py-3 px-4">Name</th>
                          <th className="py-3 px-4">Source</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5 font-mono">
                        {selectedTheharvesterScan.names.map((n) => (
                          <tr key={n.id} className="hover:bg-white/5 transition-colors">
                            <td className="py-3 px-4 text-teal-400 break-all">{n.name}</td>
                            <td className="py-3 px-4 text-slate-300">{n.source || 'unknown'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-slate-500 text-xs py-2">No results discovered.</p>
                )}
              </div>

            </div>
          ) : selectedTheharvesterScan.status === 'failed' ? (
            <div className="p-4 bg-rose-500/5 rounded-xl border border-rose-500/10 text-rose-300 text-xs font-mono leading-relaxed text-left">
              <strong>Scan Failure Description:</strong> {selectedTheharvesterScan.error_output || 'An internal scanner process error occurred.'}
            </div>
          ) : (
            <p className="text-slate-500 text-xs py-4 text-left">Scanner is currently processing target...</p>
          )}

          {/* Raw Output collapsible container */}
          <CollapsibleSection title="Raw theHarvester Output" defaultOpen={false}>
            <div className="space-y-4">
              {selectedTheharvesterScan.raw_output ? (
                <pre className="font-mono text-xs bg-black/40 border border-white/10 p-4 rounded-xl text-slate-300 overflow-x-auto whitespace-pre-wrap text-left leading-relaxed">
                  {selectedTheharvesterScan.raw_output}
                </pre>
              ) : (
                <p className="text-slate-500 text-xs py-2 text-left">No raw console stdout captured.</p>
              )}
              {selectedTheharvesterScan.error_output && selectedTheharvesterScan.status === 'failed' && (
                <div className="text-left border-t border-white/5 pt-4">
                  <span className="block text-xs font-bold text-rose-400 uppercase mb-2">Error Stream / Stderr:</span>
                  <pre className="font-mono text-xs bg-rose-950/15 border border-rose-900/30 p-4 rounded-xl text-rose-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                    {selectedTheharvesterScan.error_output}
                  </pre>
                </div>
              )}
            </div>
          </CollapsibleSection>

        </div>
      )}

      {/* Public OSINT history list */}
      <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5 mt-6">
        <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
          Public OSINT History
        </h3>
        {theharvesterHistory.length === 0 ? (
          <p className="text-slate-500 text-xs">No public OSINT history recorded for this assessment.</p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {theharvesterHistory.map((scan) => {
              const isCurrent = selectedTheharvesterScan?.id === scan.id;
              return (
                <div
                  key={scan.id}
                  onClick={() => setSelectedTheharvesterScan(scan)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer bg-white/5 hover:border-teal-500/30 ${
                    isCurrent ? 'border-teal-400 bg-teal-500/5 shadow-[0_0_15px_rgba(20,184,166,0.05)]' : 'border-white/5'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <span className="font-mono text-sm font-bold text-slate-100 truncate">
                      {scan.target?.target_value || '—'}
                    </span>
                    <div className="shrink-0">{getScanStatusBadge(scan.status)}</div>
                  </div>
                  <div className="grid grid-cols-2 gap-x-2 gap-y-1 text-xs text-slate-400 mb-3">
                    <div>Emails: <span className="text-teal-400 font-bold">{scan.emails_found || 0}</span></div>
                    <div>Hosts: <span className="text-teal-400 font-bold">{scan.hosts_found || 0}</span></div>
                    <div>IPs: <span className="text-teal-400 font-bold">{scan.ips_found || 0}</span></div>
                    <div>Names: <span className="text-teal-400 font-bold">{scan.names_found || 0}</span></div>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-semibold tracking-wide">
                    <span>
                      {scan.started_at ? new Date(scan.started_at).toLocaleDateString('en-GB', {
                        day: '2-digit',
                        month: 'short',
                        year: 'numeric'
                      }) : '—'}
                    </span>
                    <span>{scan.duration ? `${scan.duration}s` : '—'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ======================================================== */}
      {/* Shodan Public Intelligence Section */}
      {/* ======================================================== */}
      <div className="pt-6 border-t border-white/5 mt-10">
        <h2 className="text-2xl font-black mb-1">Shodan Public Intelligence</h2>
        <p className="text-slate-400 text-sm">
          Retrieve Internet-exposed information from public intelligence feeds. No active scan traffic is sent to targets.
        </p>
      </div>

      {/* Shodan Status Badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-xl bg-white/5 border border-white/5 gap-3 mt-4">
        <div className="text-left">
          <span className="block text-xs font-bold text-slate-500 uppercase tracking-wider">
            Shodan Integration status
          </span>
          <span className="font-mono text-sm text-slate-300">
            {shodanStatus.configured 
              ? (shodanStatus.available ? 'API Key Authenticated' : 'API Key Rejected or Network Issue')
              : 'API Key Not Configured'}
          </span>
        </div>
        <div>
          {shodanStatus.configured && shodanStatus.available ? (
            <span className="inline-flex items-center gap-1.5 text-teal-400 font-bold text-xs bg-teal-500/10 px-3 py-1 rounded border border-teal-500/20">
              🟢 Ready
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-rose-400 font-bold text-xs bg-rose-500/10 px-3 py-1 rounded border border-rose-500/20">
              🔴 Inactive
            </span>
          )}
        </div>
      </div>

      {/* Configuration Panel */}
      <div className="grid grid-cols-1 gap-6 mt-6">
        <div className="p-6 rounded-2xl cyber-glass space-y-4 text-left border border-white/5">
          <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase">
            Query Settings
          </h3>
          
          {shodanScanError && (
            <div className="p-3.5 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs rounded-xl mb-4 leading-relaxed whitespace-pre-wrap">
              <strong>Query Error:</strong> {shodanScanError}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Authorized Target
              </label>
              <select
                value={selectedShodanTargetId}
                onChange={(e) => setSelectedShodanTargetId(e.target.value)}
                disabled={shodanScanLoading || !shodanStatus.available}
                className="w-full px-4 py-2.5 rounded-lg bg-[#0F111E] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer text-sm"
              >
                <option value="">-- Select IP Address or Domain Target --</option>
                {targets
                  .filter((t) => (t.target_type === 'IP Address' || t.target_type === 'Domain') && t.scope_status === 'in_scope' && t.authorization_confirmed)
                  .map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.target_value} ({t.target_type})
                    </option>
                  ))}
              </select>
            </div>

            <button
              onClick={handleStartShodanScan}
              disabled={shodanScanLoading || !selectedShodanTargetId || !shodanStatus.available}
              className="w-full py-3 rounded-lg bg-teal-400 hover:bg-teal-300 disabled:opacity-40 disabled:hover:bg-teal-400 text-[#090A0F] font-bold text-sm shadow-lg shadow-teal-500/10 cursor-pointer flex items-center justify-center gap-2 transition-all duration-300"
            >
              {shodanScanLoading ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-[#090A0F]" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Querying Shodan Feed...
                </>
              ) : (
                'Query Shodan Intelligence'
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Results View */}
      {selectedShodanScan && (
        <div className="space-y-6 mt-6">
          <div className="p-6 rounded-2xl cyber-glass text-left relative overflow-hidden border border-white/5">
            <div className="absolute top-0 left-0 w-1.5 h-full bg-teal-400"></div>
            <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
              Scan Summary
            </h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-6 text-sm">
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Target</span>
                <span className="font-mono font-bold text-slate-200">{selectedShodanScan.target?.target_value || '—'}</span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Status</span>
                <div className="mt-1">{getScanStatusBadge(selectedShodanScan.status)}</div>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Duration</span>
                <span className="font-mono text-slate-300 text-xs">
                  {selectedShodanScan.duration ? `${selectedShodanScan.duration} seconds` : '—'}
                </span>
              </div>
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Queried At</span>
                <span className="font-mono text-slate-300 text-xs font-semibold">
                  {selectedShodanScan.started_at ? new Date(selectedShodanScan.started_at).toLocaleString('en-GB') : '—'}
                </span>
              </div>
            </div>
          </div>

          {selectedShodanScan.status === 'completed' && selectedShodanScan.hosts && selectedShodanScan.hosts.length > 0 ? (
            selectedShodanScan.hosts.map((host) => (
              <div key={host.id} className="space-y-6">
                
                {/* Host Meta Information */}
                <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5">
                  <h4 className="text-md font-bold text-slate-200 mb-4 border-b border-white/5 pb-2 flex items-center gap-2">
                    <span className="text-teal-400">🌐</span> Host Information: {host.ip}
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6 text-xs text-slate-400">
                    <div>
                      <span className="block text-slate-500 uppercase tracking-wider mb-1">Primary Hostname</span>
                      <span className="font-mono text-slate-200 text-sm font-semibold">{host.hostname || '—'}</span>
                    </div>
                    <div>
                      <span className="block text-slate-500 uppercase tracking-wider mb-1">Organization</span>
                      <span className="text-slate-200 text-sm font-semibold">{host.organization || '—'}</span>
                    </div>
                    <div>
                      <span className="block text-slate-500 uppercase tracking-wider mb-1">ISP</span>
                      <span className="text-slate-200 text-sm font-semibold">{host.isp || '—'}</span>
                    </div>
                    <div>
                      <span className="block text-slate-500 uppercase tracking-wider mb-1">Location</span>
                      <span className="text-slate-200 text-sm font-semibold">
                        {host.city ? `${host.city}, ` : ''}{host.country || '—'}
                      </span>
                    </div>
                    <div>
                      <span className="block text-slate-500 uppercase tracking-wider mb-1">Geo Coordinates</span>
                      <span className="font-mono text-slate-200 text-sm font-semibold">
                        {host.latitude !== null && host.longitude !== null ? `${host.latitude}, ${host.longitude}` : '—'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Exposed Services */}
                <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5">
                  <h4 className="text-md font-bold text-slate-200 mb-4 border-b border-white/5 pb-2">
                    Exposed Services ({host.services?.length || 0})
                  </h4>
                  {host.services && host.services.length > 0 ? (
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs text-left border-collapse">
                        <thead>
                          <tr className="border-b border-white/10 text-slate-500 uppercase font-semibold">
                            <th className="py-3 pr-4">Port</th>
                            <th className="py-3 px-4">Service</th>
                            <th className="py-3 px-4">Product / Version</th>
                            <th className="py-3 pl-4">Banner Preview</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5">
                          {host.services.map((svc) => (
                            <tr key={svc.id} className="hover:bg-white/5 transition-colors">
                              <td className="py-3 pr-4 font-mono font-bold text-teal-400">
                                {svc.port}/{svc.transport || 'tcp'}
                              </td>
                              <td className="py-3 px-4 font-semibold text-slate-200">
                                {svc.service || '—'}
                              </td>
                              <td className="py-3 px-4 font-mono text-slate-300">
                                {svc.product ? `${svc.product} ${svc.version || ''}` : '—'}
                              </td>
                              <td className="py-3 pl-4 font-mono text-[10px] text-slate-400 max-w-xs truncate">
                                {svc.banner ? svc.banner.split('\n')[0] : '—'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p className="text-slate-500 text-xs py-2">No exposed services returned by Shodan.</p>
                  )}
                </div>

                {/* Vulnerability Information */}
                <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5">
                  <h4 className="text-md font-bold text-slate-200 mb-4 border-b border-white/5 pb-2">
                    Discovered Vulnerabilities ({host.vulnerabilities?.length || 0})
                  </h4>
                  {host.vulnerabilities && host.vulnerabilities.length > 0 ? (
                    <div className="space-y-4">
                      {host.vulnerabilities.map((vuln) => (
                        <div key={vuln.id} className="p-4 bg-rose-500/5 rounded-xl border border-rose-500/10">
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-mono text-sm font-bold text-rose-400">
                              {vuln.cve}
                            </span>
                            <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-slate-500/10 text-slate-400 uppercase">
                              Source: {vuln.source || 'shodan'}
                            </span>
                          </div>
                          <p className="text-xs text-slate-300 leading-relaxed">
                            {vuln.description || 'No public summary is available from the Shodan feed.'}
                          </p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-500 text-xs py-2">No public vulnerabilities reported by Shodan.</p>
                  )}
                </div>

              </div>
            ))
          ) : selectedShodanScan.status === 'completed' ? (
            <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5 text-slate-400 text-sm">
              Shodan has no public intelligence information indexed for this target.
            </div>
          ) : selectedShodanScan.status === 'failed' ? (
            <div className="p-4 bg-rose-500/5 rounded-xl border border-rose-500/10 text-rose-300 text-xs font-mono leading-relaxed text-left">
              <strong>Query Failure Description:</strong> {selectedShodanScan.error_output || 'An internal scanner process error occurred.'}
            </div>
          ) : (
            <p className="text-slate-500 text-xs py-4 text-left">Scanner is currently processing target...</p>
          )}
        </div>
      )}

      {/* Shodan Scan History List */}
      <div className="p-6 rounded-2xl cyber-glass text-left border border-white/5 mt-6">
        <h3 className="text-sm font-bold tracking-wider text-slate-400 uppercase mb-4 border-b border-white/5 pb-2">
          Shodan Query History
        </h3>
        {shodanHistory.length === 0 ? (
          <p className="text-slate-500 text-xs">No Shodan queries recorded for this assessment.</p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {shodanHistory.map((scan) => {
              const isCurrent = selectedShodanScan?.id === scan.id;
              return (
                <div
                  key={scan.id}
                  onClick={() => setSelectedShodanScan(scan)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer bg-white/5 hover:border-teal-500/30 ${
                    isCurrent ? 'border-teal-400 bg-teal-500/5 shadow-[0_0_15px_rgba(20,184,166,0.05)]' : 'border-white/5'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <span className="font-mono text-sm font-bold text-slate-100 truncate">
                      {scan.target?.target_value || '—'}
                    </span>
                    <div className="shrink-0">{getScanStatusBadge(scan.status)}</div>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-semibold tracking-wide">
                    <span>
                      {scan.started_at ? new Date(scan.started_at).toLocaleDateString('en-GB', {
                        day: '2-digit',
                        month: 'short',
                        year: 'numeric'
                      }) : '—'}
                    </span>
                    <span>{scan.duration ? `${scan.duration}s` : '—'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

    </div>
  );
};

export default ReconManager;
