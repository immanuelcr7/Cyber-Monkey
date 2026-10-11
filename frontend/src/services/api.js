import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Response interceptor to handle errors globally
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error.response || error.message);
    return Promise.reject(error);
  }
);

// Assessment API functions
export const getAssessments = async () => {
  const response = await api.get('/assessments/');
  return response.data;
};

export const getAssessment = async (assessmentId) => {
  const response = await api.get(`/assessments/${assessmentId}`);
  return response.data;
};

export const createAssessment = async (data) => {
  const response = await api.post('/assessments/', data);
  return response.data;
};

export const updateAssessment = async (assessmentId, data) => {
  const response = await api.patch(`/assessments/${assessmentId}`, data);
  return response.data;
};

export const deleteAssessment = async (assessmentId) => {
  const response = await api.delete(`/assessments/${assessmentId}`);
  return response.data;
};

// Target API functions
export const getTargets = async (assessmentId) => {
  const response = await api.get(`/assessments/${assessmentId}/targets`);
  return response.data;
};

export const createTarget = async (assessmentId, data) => {
  const response = await api.post(`/assessments/${assessmentId}/targets`, data);
  return response.data;
};

export const getTarget = async (targetId) => {
  const response = await api.get(`/targets/${targetId}`);
  return response.data;
};

export const updateTarget = async (targetId, data) => {
  const response = await api.patch(`/targets/${targetId}`, data);
  return response.data;
};

export const deleteTarget = async (targetId) => {
  const response = await api.delete(`/targets/${targetId}`);
  return response.data;
};

// Recon / Nmap API functions
export const getNmapStatus = async () => {
  const response = await api.get('/recon/nmap/status');
  return response.data;
};

export const startNmapScan = async (assessmentId, targetId, scanProfile) => {
  const response = await api.post(`/assessments/${assessmentId}/recon/nmap`, {
    target_id: targetId,
    scan_profile: scanProfile
  });
  return response.data;
};

export const getNmapScans = async (assessmentId) => {
  const response = await api.get(`/assessments/${assessmentId}/recon/nmap`);
  return response.data;
};

// Recon / Subfinder API functions
export const getSubfinderStatus = async () => {
  const response = await api.get('/recon/subfinder/status');
  return response.data;
};

export const startSubfinderScan = async (assessmentId, targetId) => {
  const response = await api.post(`/assessments/${assessmentId}/recon/subfinder`, {
    target_id: targetId
  });
  return response.data;
};

export const getSubfinderScans = async (assessmentId) => {
  const response = await api.get(`/assessments/${assessmentId}/recon/subfinder`);
  return response.data;
};

// Recon / DNS API functions
export const getDnsStatus = async () => {
  const response = await api.get('/recon/dns/status');
  return response.data;
};

export const startDnsScan = async (assessmentId, targetId) => {
  const response = await api.post(`/assessments/${assessmentId}/recon/dns`, {
    target_id: targetId
  });
  return response.data;
};

export const getDnsScans = async (assessmentId) => {
  const response = await api.get(`/assessments/${assessmentId}/recon/dns`);
  return response.data;
};

// Recon / theHarvester API functions
export const getTheHarvesterStatus = async () => {
  const response = await api.get('/recon/theharvester/status');
  return response.data;
};

export const startTheHarvesterScan = async (assessmentId, targetId) => {
  const response = await api.post(`/assessments/${assessmentId}/recon/theharvester`, {
    target_id: targetId
  });
  return response.data;
};

export const getTheHarvesterScans = async (assessmentId) => {
  const response = await api.get(`/assessments/${assessmentId}/recon/theharvester`);
  return response.data;
};


// Recon / Shodan Public Intelligence API functions
export const getShodanStatus = async () => {
  const response = await api.get('/recon/shodan/status');
  return response.data;
};

export const startShodanScan = async (assessmentId, targetId) => {
  // Only send target_id - NEVER send an arbitrary IP to the backend
  const response = await api.post(`/assessments/${assessmentId}/recon/shodan`, {
    target_id: targetId
  });
  return response.data;
};

export const getShodanScans = async (assessmentId) => {
  const response = await api.get(`/assessments/${assessmentId}/recon/shodan`);
  return response.data;
};


// Vulnerability / Nuclei API functions
export const getNucleiStatus = async () => {
  const response = await api.get('/vulnerabilities/nuclei/status');
  return response.data;
};

export const startNucleiScan = async (assessmentId, targetId, profile = 'BASIC') => {
  const response = await api.post(`/assessments/${assessmentId}/vulnerabilities/nuclei`, {
    target_id: targetId,
    profile: profile
  });
  return response.data;
};

export const getNucleiScans = async (assessmentId) => {
  const response = await api.get(`/assessments/${assessmentId}/vulnerabilities/nuclei`);
  return response.data;
};

// Vulnerability / Nikto API functions
export const getNiktoStatus = async () => {
  const response = await api.get('/vulnerabilities/nikto/status');
  return response.data;
};

export const startNiktoScan = async (assessmentId, targetId, port = 80) => {
  const parsedPort = parseInt(port, 10);
  const finalPort = !isNaN(parsedPort) && parsedPort >= 1 && parsedPort <= 65535 ? parsedPort : 80;
  const response = await api.post(`/assessments/${assessmentId}/vulnerabilities/nikto`, {
    target_id: targetId,
    port: finalPort
  });
  return response.data;
};


export const getNiktoScans = async (assessmentId) => {
  const response = await api.get(`/assessments/${assessmentId}/vulnerabilities/nikto`);
  return response.data;
};

// Standalone API functions (Mode 1: Quick Scan without Assessment)
export const runStandaloneNmap = async (targetValue, scanProfile = 'service_detection', authorizationConfirmed = true) => {
  const response = await api.post('/standalone/recon/nmap', {
    target_value: targetValue,
    scan_profile: scanProfile,
    authorization_confirmed: authorizationConfirmed
  });
  return response.data;
};

export const runStandaloneSubfinder = async (targetValue, authorizationConfirmed = true) => {
  const response = await api.post('/standalone/recon/subfinder', {
    target_value: targetValue,
    authorization_confirmed: authorizationConfirmed
  });
  return response.data;
};

export const runStandaloneDns = async (targetValue, authorizationConfirmed = true) => {
  const response = await api.post('/standalone/recon/dns', {
    target_value: targetValue,
    authorization_confirmed: authorizationConfirmed
  });
  return response.data;
};

export const runStandaloneTheHarvester = async (targetValue, authorizationConfirmed = true) => {
  const response = await api.post('/standalone/recon/theharvester', {
    target_value: targetValue,
    authorization_confirmed: authorizationConfirmed
  });
  return response.data;
};

export const runStandaloneShodan = async (targetValue, authorizationConfirmed = true) => {
  const response = await api.post('/standalone/recon/shodan', {
    target_value: targetValue,
    authorization_confirmed: authorizationConfirmed
  });
  return response.data;
};

export const runStandaloneNuclei = async (targetValue, profile = 'BASIC', authorizationConfirmed = true) => {
  const response = await api.post('/standalone/vulnerabilities/nuclei', {
    target_value: targetValue,
    profile: profile,
    authorization_confirmed: authorizationConfirmed
  });
  return response.data;
};

export const runStandaloneNikto = async (targetValue, port = 80, authorizationConfirmed = true) => {
  const parsedPort = parseInt(port, 10);
  const finalPort = !isNaN(parsedPort) && parsedPort >= 1 && parsedPort <= 65535 ? parsedPort : 80;
  const response = await api.post('/standalone/vulnerabilities/nikto', {
    target_value: targetValue,
    port: finalPort,
    authorization_confirmed: authorizationConfirmed
  });
  return response.data;
};

export const runStandaloneReconScan = async (target, tool = 'theHarvester', authorizationConfirmed = true) => {
  const response = await api.post('/standalone/reconnaissance/scan', {
    target: target,
    tool: tool,
    authorization_confirmed: authorizationConfirmed
  });
  return response.data;
};

// ==========================================
// SOC ANALYST API
// ==========================================
export const getSocStatus = async () => {
  const response = await api.get('/soc/status');
  return response.data;
};

export const syncWazuhAlerts = async () => {
  const response = await api.post('/soc/wazuh/sync');
  return response.data;
};

export const getSocAlerts = async (params = {}) => {
  const response = await api.get('/soc/alerts', { params });
  return response.data;
};

export const createSocAlert = async (data) => {
  const response = await api.post('/soc/alerts', data);
  return response.data;
};

export const getSocAlert = async (alertId) => {
  const response = await api.get(`/soc/alerts/${alertId}`);
  return response.data;
};

export const updateSocAlert = async (alertId, data) => {
  const response = await api.patch(`/soc/alerts/${alertId}`, data);
  return response.data;
};

export const addSocAlertNote = async (alertId, data) => {
  const response = await api.post(`/soc/alerts/${alertId}/notes`, data);
  return response.data;
};

export const getSocIncidents = async (params = {}) => {
  const response = await api.get('/soc/incidents', { params });
  return response.data;
};

export const createSocIncident = async (data) => {
  const response = await api.post('/soc/incidents', data);
  return response.data;
};

export const getSocIncident = async (incidentId) => {
  const response = await api.get(`/soc/incidents/${incidentId}`);
  return response.data;
};

export const updateSocIncident = async (incidentId, data) => {
  const response = await api.patch(`/soc/incidents/${incidentId}`, data);
  return response.data;
};

export const addSocIncidentNote = async (incidentId, data) => {
  const response = await api.post(`/soc/incidents/${incidentId}/notes`, data);
  return response.data;
};

export const getSocAuditLogs = async () => {
  const response = await api.get('/soc/audit-logs');
  return response.data;
};

// ==========================================
// OSINT WORKSPACE API
// ==========================================
export const getOsintToolsStatus = async () => {
  const response = await api.get('/osint/tools/status');
  return response.data;
};

export const getOsintInvestigations = async (params = {}) => {
  const response = await api.get('/osint/investigations', { params });
  return response.data;
};

export const createOsintInvestigation = async (data) => {
  const response = await api.post('/osint/investigations', data);
  return response.data;
};

export const getOsintInvestigation = async (invId) => {
  const response = await api.get(`/osint/investigations/${invId}`);
  return response.data;
};

export const updateOsintInvestigation = async (invId, data) => {
  const response = await api.patch(`/osint/investigations/${invId}`, data);
  return response.data;
};

export const runOsintScan = async (invId, data) => {
  const response = await api.post(`/osint/investigations/${invId}/scan`, data);
  return response.data;
};

export const addOsintNote = async (invId, data) => {
  const response = await api.post(`/osint/investigations/${invId}/notes`, data);
  return response.data;
};

export const exportOsintInvestigation = async (invId) => {
  const response = await api.get(`/osint/investigations/${invId}/export`);
  return response.data;
};

// ==========================================
// MALWARE ANALYSIS WORKSPACE API
// ==========================================
export const getMalwareStatus = async () => {
  const response = await api.get('/malware/status');
  return response.data;
};

export const getMalwareJobs = async (params = {}) => {
  const response = await api.get('/malware/jobs', { params });
  return response.data;
};

export const uploadMalwareSample = async (formData) => {
  const response = await api.post('/malware/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  });
  return response.data;
};

export const getMalwareJob = async (jobId) => {
  const response = await api.get(`/malware/jobs/${jobId}`);
  return response.data;
};

export const addMalwareNote = async (jobId, data) => {
  const response = await api.post(`/malware/jobs/${jobId}/notes`, data);
  return response.data;
};

export const exportMalwareReport = async (jobId) => {
  const response = await api.get(`/malware/jobs/${jobId}/export`);
  return response.data;
};

// ==========================================
// DIGITAL FORENSICS WORKSPACE API
// ==========================================
export const getForensicsStatus = async () => {
  const response = await api.get('/forensics/status');
  return response.data;
};

export const getForensicCases = async (params = {}) => {
  const response = await api.get('/forensics/cases', { params });
  return response.data;
};

export const createForensicCase = async (data) => {
  const response = await api.post('/forensics/cases', data);
  return response.data;
};

export const getForensicCase = async (caseId) => {
  const response = await api.get(`/forensics/cases/${caseId}`);
  return response.data;
};

export const updateForensicCase = async (caseId, data) => {
  const response = await api.patch(`/forensics/cases/${caseId}`, data);
  return response.data;
};

export const acquireEvidence = async (caseId, formData) => {
  const response = await api.post(`/forensics/cases/${caseId}/evidence`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  });
  return response.data;
};

export const verifyEvidenceIntegrity = async (evidenceId) => {
  const response = await api.post(`/forensics/evidence/${evidenceId}/verify-integrity`);
  return response.data;
};

export const addChainOfCustody = async (evidenceId, data) => {
  const response = await api.post(`/forensics/evidence/${evidenceId}/custody`, data);
  return response.data;
};

export const addForensicTimelineEvent = async (caseId, data) => {
  const response = await api.post(`/forensics/cases/${caseId}/timeline`, data);
  return response.data;
};

export const addForensicNote = async (caseId, data) => {
  const response = await api.post(`/forensics/cases/${caseId}/notes`, data);
  return response.data;
};

export const exportForensicCaseJson = async (caseId) => {
  const response = await api.get(`/forensics/cases/${caseId}/export/json`);
  return response.data;
};

export const exportForensicTimelineCsv = async (caseId) => {
  const response = await api.get(`/forensics/cases/${caseId}/export/timeline-csv`, {
    responseType: 'blob'
  });
  return response.data;
};

// ==========================================
// NETWORK MONITORING WORKSPACE API
// ==========================================
export const getNetworkHealthSummary = async () => {
  const response = await api.get('/network-monitoring/health-summary');
  return response.data;
};

export const getNetworkTelemetryStatus = async () => {
  const response = await api.get('/network-monitoring/telemetry/status');
  return response.data;
};

export const getNetworkAssets = async (params = {}) => {
  const response = await api.get('/network-monitoring/assets', { params });
  return response.data;
};

export const createNetworkAsset = async (data) => {
  const response = await api.post('/network-monitoring/assets', data);
  return response.data;
};

export const getNetworkAsset = async (assetId) => {
  const response = await api.get(`/network-monitoring/assets/${assetId}`);
  return response.data;
};

export const updateNetworkAsset = async (assetId, data) => {
  const response = await api.patch(`/network-monitoring/assets/${assetId}`, data);
  return response.data;
};

export const deleteNetworkAsset = async (assetId) => {
  const response = await api.delete(`/network-monitoring/assets/${assetId}`);
  return response.data;
};

export const addNetworkService = async (assetId, data) => {
  const response = await api.post(`/network-monitoring/assets/${assetId}/services`, data);
  return response.data;
};

export const checkAssetAvailability = async (assetId) => {
  const response = await api.post(`/network-monitoring/assets/${assetId}/check`);
  return response.data;
};

export const getNetworkEvents = async (params = {}) => {
  const response = await api.get('/network-monitoring/events', { params });
  return response.data;
};

export const discoverAssetsNmap = async (targetValue, authConfirmed = true) => {
  const response = await api.post(`/network-monitoring/discover-nmap?target_value=${encodeURIComponent(targetValue)}&authorization_confirmed=${authConfirmed}`);
  return response.data;
};

// ==========================================
// CENTRAL INTEGRATIONS & AI ASSISTANT API
// ==========================================
export const getAllIntegrationsStatus = async () => {
  const response = await api.get('/integrations/status');
  return response.data;
};

export const getAiStatus = async () => {
  const response = await api.get('/ai/status');
  return response.data;
};

export const analyzeWithAi = async (data) => {
  const response = await api.post('/ai/analyze', data);
  return response.data;
};

export default api;




