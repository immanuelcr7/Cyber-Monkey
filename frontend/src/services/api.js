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

export default api;




