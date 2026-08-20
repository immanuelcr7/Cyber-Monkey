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

export default api;
