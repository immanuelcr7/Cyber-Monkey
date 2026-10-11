import React, { useState, useEffect } from 'react';
import {
  getNetworkHealthSummary,
  getNetworkTelemetryStatus,
  getNetworkAssets,
  createNetworkAsset,
  getNetworkAsset,
  deleteNetworkAsset,
  addNetworkService,
  checkAssetAvailability,
  getNetworkEvents,
  discoverAssetsNmap
} from '../services/api';
import Navbar from '../components/Navbar';
import AiCyberAssistantModal from '../components/AiCyberAssistantModal';
import IntegrationsModal from '../components/IntegrationsModal';

const NetworkMonitoringWorkspace = () => {
  const [healthSummary, setHealthSummary] = useState(null);
  const [telemetryStatus, setTelemetryStatus] = useState(null);
  const [assets, setAssets] = useState([]);
  const [events, setEvents] = useState([]);
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [loading, setLoading] = useState(true);
  const [probingId, setProbingId] = useState(null);

  // Tabs: 'assets' | 'events'
  const [activeTab, setActiveTab] = useState('assets');

  // Modals
  const [isAddAssetOpen, setIsAddAssetOpen] = useState(false);
  const [isAddServiceOpen, setIsAddServiceOpen] = useState(false);
  const [isNmapDiscoveryOpen, setIsNmapDiscoveryOpen] = useState(false);
  const [isAiOpen, setIsAiOpen] = useState(false);
  const [isIntegrationsOpen, setIsIntegrationsOpen] = useState(false);

  // Forms
  const [assetForm, setAssetForm] = useState({
    ip_address: '',
    hostname: '',
    asset_type: 'server',
    monitored: true,
    ports: '80, 443, 22',
    notes: ''
  });

  const [serviceForm, setServiceForm] = useState({
    port: 8080,
    protocol: 'TCP',
    service_name: 'http-alt'
  });

  const [discoveryForm, setDiscoveryForm] = useState({
    target: '127.0.0.1',
    authorization_confirmed: false
  });
  const [discoveryLoading, setDiscoveryLoading] = useState(false);
  const [discoveryResult, setDiscoveryResult] = useState(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [health, telemetry, assetList, eventList] = await Promise.all([
        getNetworkHealthSummary().catch(() => null),
        getNetworkTelemetryStatus().catch(() => null),
        getNetworkAssets(),
        getNetworkEvents()
      ]);
      setHealthSummary(health);
      setTelemetryStatus(telemetry);
      setAssets(assetList);
      setEvents(eventList);
      if (assetList.length > 0) {
        setSelectedAsset(assetList[0]);
      }
    } catch (err) {
      console.error('Error loading network monitoring data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCreateAsset = async (e) => {
    e.preventDefault();
    const portsArray = assetForm.ports
      .split(',')
      .map(p => parseInt(p.trim(), 10))
      .filter(p => !isNaN(p) && p >= 1 && p <= 65535);

    try {
      const created = await createNetworkAsset({
        ip_address: assetForm.ip_address.trim(),
        hostname: assetForm.hostname.trim() || undefined,
        asset_type: assetForm.asset_type,
        monitored: assetForm.monitored,
        notes: assetForm.notes || undefined,
        ports: portsArray
      });
      setAssets([created, ...assets]);
      setSelectedAsset(created);
      setIsAddAssetOpen(false);
      setAssetForm({
        ip_address: '',
        hostname: '',
        asset_type: 'server',
        monitored: true,
        ports: '80, 443, 22',
        notes: ''
      });
      loadData();
    } catch (err) {
      alert('Failed to register asset: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleProbeAsset = async (assetId) => {
    setProbingId(assetId);
    try {
      const res = await checkAssetAvailability(assetId);
      // Reload assets
      const updatedList = await getNetworkAssets();
      setAssets(updatedList);
      const sel = updatedList.find(a => a.id === assetId);
      if (sel) setSelectedAsset(sel);
      const evts = await getNetworkEvents();
      setEvents(evts);
    } catch (err) {
      alert('Probe error: ' + (err.response?.data?.detail || err.message));
    } finally {
      setProbingId(null);
    }
  };

  const handleAddService = async (e) => {
    e.preventDefault();
    if (!selectedAsset) return;
    try {
      await addNetworkService(selectedAsset.id, {
        port: parseInt(serviceForm.port, 10),
        protocol: serviceForm.protocol,
        service_name: serviceForm.service_name
      });
      setIsAddServiceOpen(false);
      const detail = await getNetworkAsset(selectedAsset.id);
      setSelectedAsset(detail);
      const updatedList = await getNetworkAssets();
      setAssets(updatedList);
    } catch (err) {
      alert('Failed to add service: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleDeleteAsset = async (assetId) => {
    if (!confirm('Are you sure you want to remove this asset from monitoring?')) return;
    try {
      await deleteNetworkAsset(assetId);
      const remaining = assets.filter(a => a.id !== assetId);
      setAssets(remaining);
      setSelectedAsset(remaining[0] || null);
      loadData();
    } catch (err) {
      alert('Failed to delete asset: ' + err.message);
    }
  };

  const handleNmapDiscovery = async (e) => {
    e.preventDefault();
    if (!discoveryForm.authorization_confirmed) {
      alert('Authorization must be explicitly confirmed for active network scans.');
      return;
    }
    setDiscoveryLoading(true);
    setDiscoveryResult(null);
    try {
      const res = await discoverAssetsNmap(discoveryForm.target, true);
      setDiscoveryResult(res);
      loadData();
    } catch (err) {
      alert('Discovery scan failed: ' + (err.response?.data?.detail || err.message));
    } finally {
      setDiscoveryLoading(false);
    }
  };

  return (
    <div className="min-h-screen p-4 md:p-8 relative bg-[#090A0F] text-slate-100 flex flex-col justify-between">
      {/* Background cyber glow */}
      <div className="absolute top-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-blue-500/5 blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-indigo-500/10 blur-[120px] pointer-events-none"></div>

      <div className="max-w-7xl w-full mx-auto z-10 flex-1">
        <Navbar
          activeWorkspaceTitle="Network Monitoring Workspace"
          onOpenAi={() => setIsAiOpen(true)}
          onOpenIntegrations={() => setIsIntegrationsOpen(true)}
        />

        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-300 text-xs font-semibold uppercase tracking-wider mb-2">
              📡 Active Network Telemetry
            </div>
            <h1 className="text-3xl md:text-4xl font-black bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-100 to-blue-400">
              Network Monitoring Workspace
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Asset inventory, service availability probes, TCP port monitoring, and network change anomaly detection.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsNmapDiscoveryOpen(true)}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-white/10 hover:bg-white/15 text-slate-200 border border-white/10 transition cursor-pointer flex items-center gap-1.5"
            >
              <span>🔍</span>
              <span>Nmap Discovery</span>
            </button>
            <button
              onClick={() => setIsAddAssetOpen(true)}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-blue-500 hover:bg-blue-400 text-white shadow-lg shadow-blue-500/20 transition cursor-pointer flex items-center gap-1.5"
            >
              <span>+</span>
              <span>Register Asset</span>
            </button>
          </div>
        </div>

        {/* Telemetry Status Ribbon */}
        <div className="p-4 rounded-2xl cyber-glass border border-blue-500/20 mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🌐</span>
            <div>
              <div className="font-bold text-slate-200">
                Network Telemetry Data Sources
              </div>
              <p className="text-slate-400 text-[11px]">
                Active socket TCP port probing is enabled. Passive packet monitoring requires connected Zeek or Suricata sensor.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="bg-white/5 px-2.5 py-1 rounded text-[10px] font-mono text-amber-300">
              Zeek: {telemetryStatus?.zeek?.status === 'connected' ? 'Connected' : 'Not Connected'}
            </span>
            <span className="bg-white/5 px-2.5 py-1 rounded text-[10px] font-mono text-amber-300">
              Suricata: {telemetryStatus?.suricata?.status === 'connected' ? 'Connected' : 'Not Connected'}
            </span>
            <button
              onClick={() => setIsIntegrationsOpen(true)}
              className="text-blue-400 hover:underline text-[11px] ml-2"
            >
              Manage &rarr;
            </button>
          </div>
        </div>

        {/* Metric Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="p-4 rounded-xl cyber-glass border border-white/5">
            <span className="text-[11px] font-bold uppercase text-slate-400 tracking-wider">Total Assets</span>
            <div className="text-2xl font-black text-white mt-1">{assets.length}</div>
            <span className="text-[10px] text-slate-500 font-mono">Registered endpoints</span>
          </div>

          <div className="p-4 rounded-xl cyber-glass border border-white/5">
            <span className="text-[11px] font-bold uppercase text-teal-400 tracking-wider">Online (UP)</span>
            <div className="text-2xl font-black text-teal-300 mt-1">
              {assets.filter(a => a.status === 'up').length}
            </div>
            <span className="text-[10px] text-slate-500 font-mono">TCP probe responsive</span>
          </div>

          <div className="p-4 rounded-xl cyber-glass border border-white/5">
            <span className="text-[11px] font-bold uppercase text-rose-400 tracking-wider">Offline (DOWN)</span>
            <div className="text-2xl font-black text-rose-300 mt-1">
              {assets.filter(a => a.status === 'down').length}
            </div>
            <span className="text-[10px] text-slate-500 font-mono">Unreachable ports</span>
          </div>

          <div className="p-4 rounded-xl cyber-glass border border-white/5">
            <span className="text-[11px] font-bold uppercase text-blue-400 tracking-wider">Network Events</span>
            <div className="text-2xl font-black text-blue-300 mt-1">
              {events.length}
            </div>
            <span className="text-[10px] text-slate-500 font-mono">State transitions logged</span>
          </div>
        </div>

        {/* View Tabs */}
        <div className="flex items-center gap-2 border-b border-white/10 mb-6 pb-2">
          <button
            onClick={() => setActiveTab('assets')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
              activeTab === 'assets'
                ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                : 'text-slate-400 hover:text-white hover:bg-white/5'
            }`}
          >
            🖥️ Asset Inventory ({assets.length})
          </button>
          <button
            onClick={() => setActiveTab('events')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
              activeTab === 'events'
                ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                : 'text-slate-400 hover:text-white hover:bg-white/5'
            }`}
          >
            ⚡ Anomaly & Event Timeline ({events.length})
          </button>
        </div>

        {/* TAB 1: ASSETS */}
        {activeTab === 'assets' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Asset List */}
            <div className="lg:col-span-2 space-y-3">
              {assets.length === 0 ? (
                <div className="py-16 text-center cyber-glass rounded-2xl border border-white/5 p-8">
                  <span className="text-3xl block mb-2">🖥️</span>
                  <h4 className="font-bold text-slate-300">No Assets Registered</h4>
                  <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1 mb-4">
                    Register an authorized IP address or discover network targets using Nmap.
                  </p>
                  <button
                    onClick={() => setIsAddAssetOpen(true)}
                    className="px-4 py-2 rounded-xl text-xs font-semibold bg-blue-500/20 text-blue-300 border border-blue-500/30 cursor-pointer"
                  >
                    Register Asset &rarr;
                  </button>
                </div>
              ) : (
                assets.map((asset) => {
                  const isSelected = selectedAsset?.id === asset.id;
                  const isUp = asset.status === 'up';
                  return (
                    <div
                      key={asset.id}
                      onClick={() => setSelectedAsset(asset)}
                      className={`p-4 rounded-xl border transition cursor-pointer ${
                        isSelected
                          ? 'bg-blue-500/10 border-blue-500/30 shadow-lg shadow-blue-500/5'
                          : 'bg-white/[0.02] border-white/5 hover:border-white/10 hover:bg-white/[0.04]'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-3 mb-2">
                        <div className="flex items-center gap-2">
                          <span className={`w-2.5 h-2.5 rounded-full ${isUp ? 'bg-teal-400 animate-pulse' : (asset.status === 'down' ? 'bg-rose-400' : 'bg-slate-500')}`} />
                          <span className="font-mono text-sm font-bold text-white">{asset.ip_address}</span>
                          {asset.hostname && (
                            <span className="text-xs text-slate-400 font-medium">({asset.hostname})</span>
                          )}
                          <span className="text-[10px] uppercase font-mono bg-white/5 px-1.5 py-0.5 rounded text-slate-400">
                            {asset.asset_type}
                          </span>
                        </div>

                        <div className="flex items-center gap-2">
                          {asset.response_time_ms && (
                            <span className="font-mono text-[10px] text-teal-300 bg-teal-500/10 px-2 py-0.5 rounded">
                              {asset.response_time_ms} ms
                            </span>
                          )}
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleProbeAsset(asset.id);
                            }}
                            disabled={probingId === asset.id}
                            className="px-2.5 py-1 text-xs rounded-lg bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 font-semibold transition cursor-pointer"
                          >
                            {probingId === asset.id ? 'Probing...' : 'Probe Ports'}
                          </button>
                        </div>
                      </div>

                      <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-white/5">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-[10px] uppercase text-slate-500">Ports:</span>
                          {asset.services?.length > 0 ? (
                            asset.services.map(s => (
                              <span key={s.id} className="font-mono text-[10px] bg-white/5 px-1.5 py-0.5 rounded text-slate-300">
                                {s.port}/{s.protocol} ({s.status})
                              </span>
                            ))
                          ) : (
                            <span className="text-[10px] text-slate-500">None registered</span>
                          )}
                        </div>

                        <span className="text-[10px] text-slate-500 font-mono">
                          Last seen: {new Date(asset.last_seen).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Right Column: Asset Details & Services */}
            <div className="cyber-glass rounded-2xl border border-white/10 p-5 h-fit sticky top-6">
              {selectedAsset ? (
                <div className="space-y-4">
                  <div className="flex items-start justify-between pb-3 border-b border-white/10">
                    <div>
                      <div className="font-mono text-base font-bold text-white">{selectedAsset.ip_address}</div>
                      <div className="text-xs text-slate-400 mt-0.5">{selectedAsset.hostname || 'No hostname set'}</div>
                    </div>
                    <button
                      onClick={() => setIsAiOpen(true)}
                      className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-teal-400 to-indigo-500 text-[#090A0F] shadow cursor-pointer flex items-center gap-1"
                    >
                      <span>🧠</span>
                      <span>AI Posture</span>
                    </button>
                  </div>

                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between py-1 border-b border-white/5">
                      <span className="text-slate-400">Status:</span>
                      <span className={`font-bold uppercase ${selectedAsset.status === 'up' ? 'text-teal-300' : 'text-rose-400'}`}>
                        {selectedAsset.status}
                      </span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-white/5">
                      <span className="text-slate-400">Asset Type:</span>
                      <span className="capitalize text-slate-200">{selectedAsset.asset_type}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-white/5">
                      <span className="text-slate-400">Average Latency:</span>
                      <span className="font-mono text-slate-200">{selectedAsset.response_time_ms ? `${selectedAsset.response_time_ms} ms` : 'N/A'}</span>
                    </div>
                    {selectedAsset.notes && (
                      <div className="py-1">
                        <span className="text-slate-400 block mb-0.5">Notes:</span>
                        <p className="text-slate-300 italic">{selectedAsset.notes}</p>
                      </div>
                    )}
                  </div>

                  {/* Monitored Services List */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                        Monitored Services / Ports ({selectedAsset.services?.length || 0})
                      </label>
                      <button
                        onClick={() => setIsAddServiceOpen(true)}
                        className="text-xs text-blue-400 hover:text-blue-300 font-semibold cursor-pointer"
                      >
                        + Add Port
                      </button>
                    </div>

                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {selectedAsset.services?.map((svc) => (
                        <div key={svc.id} className="p-2.5 rounded-xl bg-white/[0.02] border border-white/5 flex items-center justify-between text-xs">
                          <div>
                            <div className="font-mono font-bold text-white text-xs">
                              Port {svc.port}/{svc.protocol}
                            </div>
                            <span className="text-[10px] text-slate-400">{svc.service_name}</span>
                          </div>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${svc.status === 'open' ? 'bg-teal-500/10 text-teal-300' : 'bg-rose-500/10 text-rose-300'}`}>
                            {svc.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="pt-3 border-t border-white/10 flex justify-between">
                    <button
                      onClick={() => handleProbeAsset(selectedAsset.id)}
                      disabled={probingId === selectedAsset.id}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-500 text-white cursor-pointer"
                    >
                      {probingId === selectedAsset.id ? 'Probing...' : 'Probe Now'}
                    </button>
                    <button
                      onClick={() => handleDeleteAsset(selectedAsset.id)}
                      className="px-3 py-1.5 rounded-lg text-xs text-rose-400 hover:bg-rose-500/10 transition cursor-pointer"
                    >
                      Delete Asset
                    </button>
                  </div>
                </div>
              ) : (
                <div className="py-12 text-center text-slate-500 text-xs">
                  Select an asset to view monitored ports, probe latency, and inspect status.
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: EVENTS & ANOMALIES */}
        {activeTab === 'events' && (
          <div className="cyber-glass rounded-2xl border border-white/10 p-6 space-y-4">
            <h3 className="font-bold text-base text-white">Network Anomaly & State Transition Log</h3>
            {events.length === 0 ? (
              <p className="text-xs text-slate-500 py-8 text-center">
                No anomalous network events recorded yet. Probes that detect host downtime or port state changes will log here.
              </p>
            ) : (
              <div className="space-y-2">
                {events.map((evt) => (
                  <div key={evt.id} className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5 flex items-start gap-3 text-xs">
                    <span className={`font-mono text-[10px] font-bold uppercase px-2 py-0.5 rounded shrink-0 ${
                      evt.severity === 'high' ? 'bg-rose-500/10 text-rose-300 border border-rose-500/20' : 'bg-blue-500/10 text-blue-300 border border-blue-500/20'
                    }`}>
                      {evt.event_type}
                    </span>
                    <div className="flex-1">
                      <p className="text-slate-200">{evt.message}</p>
                    </div>
                    <span className="font-mono text-[10px] text-slate-500 shrink-0">
                      {new Date(evt.timestamp).toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

      </div>

      {/* REGISTER ASSET MODAL */}
      {isAddAssetOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-[#0e1017] border border-white/10 rounded-2xl p-6 relative">
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
              <h3 className="font-bold text-base text-white">Register Monitored Network Asset</h3>
              <button
                onClick={() => setIsAddAssetOpen(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateAsset} className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">IP Address</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g., 192.168.1.1"
                    value={assetForm.ip_address}
                    onChange={(e) => setAssetForm({ ...assetForm, ip_address: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Hostname (Optional)</label>
                  <input
                    type="text"
                    placeholder="e.g., core-router-01"
                    value={assetForm.hostname}
                    onChange={(e) => setAssetForm({ ...assetForm, hostname: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Asset Type</label>
                  <select
                    value={assetForm.asset_type}
                    onChange={(e) => setAssetForm({ ...assetForm, asset_type: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  >
                    <option value="server" className="bg-[#0e1017]">Server</option>
                    <option value="router" className="bg-[#0e1017]">Router</option>
                    <option value="switch" className="bg-[#0e1017]">Switch</option>
                    <option value="firewall" className="bg-[#0e1017]">Firewall</option>
                    <option value="workstation" className="bg-[#0e1017]">Workstation</option>
                    <option value="iot" className="bg-[#0e1017]">IoT Device</option>
                  </select>
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Initial Ports</label>
                  <input
                    type="text"
                    placeholder="80, 443, 22"
                    value={assetForm.ports}
                    onChange={(e) => setAssetForm({ ...assetForm, ports: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Notes</label>
                <textarea
                  rows={2}
                  value={assetForm.notes}
                  onChange={(e) => setAssetForm({ ...assetForm, notes: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAddAssetOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs bg-white/10 hover:bg-white/15 text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-blue-500 hover:bg-blue-400 text-white"
                >
                  Register Asset
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ADD SERVICE MODAL */}
      {isAddServiceOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-sm bg-[#0e1017] border border-white/10 rounded-2xl p-6 relative">
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
              <h3 className="font-bold text-base text-white">Add Monitored Port</h3>
              <button
                onClick={() => setIsAddServiceOpen(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleAddService} className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Port</label>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    required
                    value={serviceForm.port}
                    onChange={(e) => setServiceForm({ ...serviceForm, port: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Protocol</label>
                  <select
                    value={serviceForm.protocol}
                    onChange={(e) => setServiceForm({ ...serviceForm, protocol: e.target.value })}
                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                  >
                    <option value="TCP" className="bg-[#0e1017]">TCP</option>
                    <option value="UDP" className="bg-[#0e1017]">UDP</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Service Name</label>
                <input
                  type="text"
                  value={serviceForm.service_name}
                  onChange={(e) => setServiceForm({ ...serviceForm, service_name: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAddServiceOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs bg-white/10 text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-blue-500 text-white"
                >
                  Add Port
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* NMAP DISCOVERY MODAL */}
      {isNmapDiscoveryOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-[#0e1017] border border-white/10 rounded-2xl p-6 relative">
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
              <h3 className="font-bold text-base text-white">Nmap Network Asset Discovery</h3>
              <button
                onClick={() => setIsNmapDiscoveryOpen(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleNmapDiscovery} className="space-y-4">
              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">Target Host / Subnet</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., 127.0.0.1 or 192.168.1.1"
                  value={discoveryForm.target}
                  onChange={(e) => setDiscoveryForm({ ...discoveryForm, target: e.target.value })}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-blue-400"
                />
              </div>

              <div className="p-3 rounded-xl bg-blue-500/5 border border-blue-500/20 flex items-start gap-3">
                <input
                  type="checkbox"
                  id="disc_auth"
                  checked={discoveryForm.authorization_confirmed}
                  onChange={(e) => setDiscoveryForm({ ...discoveryForm, authorization_confirmed: e.target.checked })}
                  className="mt-0.5 rounded text-blue-400 focus:ring-0"
                />
                <label htmlFor="disc_auth" className="text-xs text-slate-300">
                  I confirm explicit authorization to run active Nmap discovery against this target.
                </label>
              </div>

              {discoveryResult && (
                <div className="p-3 rounded-xl bg-teal-500/10 border border-teal-500/20 text-xs text-teal-300 font-mono">
                  Discovery complete: {discoveryResult.ports_discovered} ports found. Ingested into asset inventory.
                </div>
              )}

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsNmapDiscoveryOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs bg-white/10 text-white"
                >
                  Close
                </button>
                <button
                  type="submit"
                  disabled={discoveryLoading}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-blue-500 hover:bg-blue-400 text-white disabled:opacity-50"
                >
                  {discoveryLoading ? 'Scanning Network...' : 'Run Discovery'}
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
        initialWorkspace="network"
        initialEvidence={healthSummary ? {
          total_assets: healthSummary.total_assets,
          up_assets: healthSummary.up_assets,
          down_assets: healthSummary.down_assets,
          events_count: events.length,
          sample_events: events.slice(0, 5)
        } : null}
        initialTask="explain"
      />

      {/* INTEGRATIONS MODAL */}
      <IntegrationsModal
        isOpen={isIntegrationsOpen}
        onClose={() => setIsIntegrationsOpen(false)}
      />
    </div>
  );
};

export default NetworkMonitoringWorkspace;
