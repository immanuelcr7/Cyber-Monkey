import React, { useEffect, useState } from 'react';
import { useParams, useNavigate, Link, useSearchParams } from 'react-router-dom';
import { getAssessment, updateAssessment, deleteAssessment } from '../services/api';
import TargetManager from '../components/TargetManager';
import ReconManager from '../components/ReconManager';
import VulnerabilityManager from '../components/VulnerabilityManager';

const AssessmentWorkspace = () => {
  const { assessmentId, module } = useParams();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Tab mapping for module sub-routes or query parameters
  const getTabFromRoute = () => {
    if (module) {
      if (['reconnaissance', 'recon'].includes(module.toLowerCase())) return 'reconnaissance';
      if (['network-scanning', 'scanning'].includes(module.toLowerCase())) return 'network-scanning';
      if (['web-testing', 'web'].includes(module.toLowerCase())) return 'web-testing';
      if (['vulnerabilities', 'vulns', 'vulnerability'].includes(module.toLowerCase())) return 'vulnerabilities';
      if (['findings'].includes(module.toLowerCase())) return 'findings';
      if (['ai-analysis', 'ai'].includes(module.toLowerCase())) return 'ai-analysis';
      if (['reports'].includes(module.toLowerCase())) return 'reports';
      if (['overview', 'targets'].includes(module.toLowerCase())) return 'overview';
    }
    const tabParam = searchParams.get('tab');
    if (tabParam) {
      if (['reconnaissance', 'recon'].includes(tabParam.toLowerCase())) return 'reconnaissance';
      if (['network-scanning', 'scanning'].includes(tabParam.toLowerCase())) return 'network-scanning';
      if (['web-testing', 'web'].includes(tabParam.toLowerCase())) return 'web-testing';
      if (['vulnerabilities', 'vulns', 'vulnerability'].includes(tabParam.toLowerCase())) return 'vulnerabilities';
      if (['findings'].includes(tabParam.toLowerCase())) return 'findings';
      if (['ai-analysis', 'ai'].includes(tabParam.toLowerCase())) return 'ai-analysis';
      if (['reports'].includes(tabParam.toLowerCase())) return 'reports';
    }
    return 'overview';
  };

  const [assessment, setAssessment] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notFound, setNotFound] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [activeTab, setActiveTab] = useState(getTabFromRoute());

  useEffect(() => {
    setActiveTab(getTabFromRoute());
  }, [module, searchParams]);

  // Edit Form State
  const [editForm, setEditForm] = useState({
    name: '',
    organization: '',
    assessment_type: '',
    description: '',
    start_date: '',
    end_date: '',
    status: ''
  });
  const [editLoading, setEditLoading] = useState(false);
  const [editError, setEditError] = useState('');

  const types = [
    'External Network',
    'Internal Network',
    'Web Application',
    'API',
    'Cloud',
    'Other'
  ];

  const statuses = [
    { value: 'active', label: 'Active' },
    { value: 'completed', label: 'Completed' },
    { value: 'archived', label: 'Archived' }
  ];

  const fetchDetails = async () => {
    try {
      setLoading(true);
      setNotFound(false);
      const data = await getAssessment(assessmentId);
      setAssessment(data);
      setEditForm({
        name: data.name || '',
        organization: data.organization || '',
        assessment_type: data.assessment_type || '',
        description: data.description || '',
        start_date: data.start_date || '',
        end_date: data.end_date || '',
        status: data.status || 'active'
      });
      setError('');
    } catch (err) {
      if (err.response && err.response.status === 404) {
        setNotFound(true);
      } else if (!err.response) {
        setError('Backend connection unavailable. Please make sure the Cyber Monkey API is running.');
      } else {
        setError('Unable to load assessment.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (assessmentId) {
      fetchDetails();
    }
  }, [assessmentId]);

  const handleEditChange = (e) => {
    const { name, value } = e.target;
    setEditForm((prev) => ({
      ...prev,
      [name]: value
    }));
  };

  const handleEditSubmit = async (e) => {
    e.preventDefault();
    const nameTrimmed = editForm.name.trim();
    if (!nameTrimmed) {
      setEditError('Assessment Name is required.');
      return;
    }
    if (!editForm.assessment_type) {
      setEditError('Assessment Type is required.');
      return;
    }

    try {
      setEditLoading(true);
      setEditError('');

      const payload = {
        name: nameTrimmed,
        organization: editForm.organization.trim() || null,
        assessment_type: editForm.assessment_type,
        description: editForm.description.trim() || null,
        start_date: editForm.start_date || null,
        end_date: editForm.end_date || null,
        status: editForm.status
      };

      await updateAssessment(assessmentId, payload);
      setIsEditing(false);
      await fetchDetails();
    } catch (err) {
      setEditError('Unable to update assessment.');
    } finally {
      setEditLoading(false);
    }
  };

  const handleConfirmedDelete = async () => {
    try {
      setLoading(true);
      setError('');
      await deleteAssessment(assessmentId);
      setShowDeleteModal(false);
      navigate('/pentest/assessments');
    } catch (err) {
      setShowDeleteModal(false);
      setError('Unable to delete assessment.');
      setLoading(false);
    }
  };

  const getStatusBadge = (status) => {
    const s = String(status || '').toUpperCase();
    switch (status) {
      case 'active':
        return (
          <span className="px-2 py-0.5 text-xs font-bold rounded bg-teal-500/10 text-teal-300 border border-teal-500/20">
            {s}
          </span>
        );
      case 'completed':
        return (
          <span className="px-2 py-0.5 text-xs font-bold rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
            {s}
          </span>
        );
      case 'archived':
        return (
          <span className="px-2 py-0.5 text-xs font-bold rounded bg-white/5 text-slate-500 border border-white/5">
            {s}
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 text-xs font-bold rounded bg-slate-500/10 text-slate-300 border border-slate-500/20">
            {s}
          </span>
        );
    }
  };

  const tabs = [
    { id: 'overview', label: '🎯 Overview & Targets', route: `/pentest/assessments/${assessmentId}` },
    { id: 'reconnaissance', label: '🔍 Reconnaissance', route: `/pentest/assessments/${assessmentId}/reconnaissance` },
    { id: 'network-scanning', label: '📡 Network Scanning', route: `/pentest/assessments/${assessmentId}/network-scanning` },
    { id: 'web-testing', label: '🌐 Web Application Testing', route: `/pentest/assessments/${assessmentId}/web-testing` },
    { id: 'vulnerabilities', label: '🛡️ Vulnerability Assessment', route: `/pentest/assessments/${assessmentId}/vulnerabilities` },
    { id: 'findings', label: '🪲 Findings', route: `/pentest/assessments/${assessmentId}/findings` },
    { id: 'ai-analysis', label: '🧠 AI Security Analysis', route: `/pentest/assessments/${assessmentId}/ai-analysis` },
    { id: 'reports', label: '📄 Reports', route: `/pentest/assessments/${assessmentId}/reports` },
  ];

  const handleTabClick = (tab) => {
    setActiveTab(tab.id);
    navigate(tab.route);
  };

  if (loading && !showDeleteModal) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-[#090A0F] text-slate-100">
        <svg className="animate-spin h-8 w-8 text-teal-400 mb-4" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        <p className="text-slate-400 text-sm">Opening assessment workspace...</p>
      </div>
    );
  }

  if (notFound || !assessment) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-[#090A0F] text-slate-100">
        <div className="p-8 max-w-md w-full text-center cyber-glass rounded-2xl border border-rose-500/20 bg-rose-500/5">
          <div className="text-5xl mb-4">⚠️</div>
          <h3 className="text-2xl font-black mb-2 text-rose-400">Assessment Not Found</h3>
          <p className="text-slate-400 text-sm mb-8">The requested assessment record could not be located.</p>
          <button
            onClick={() => navigate('/pentest/assessments')}
            className="w-full py-2.5 bg-teal-400 hover:bg-teal-300 text-[#090A0F] font-bold rounded-lg text-sm transition-all"
          >
            Back to Assessments
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-6 md:p-12 relative overflow-hidden bg-[#090A0F] text-slate-100">
      
      {/* Decorative gradients */}
      <div className="absolute top-[-10%] left-[-10%] w-[35%] h-[35%] rounded-full bg-teal-500/5 blur-[120px] pointer-events-none"></div>

      <div className="max-w-6xl mx-auto z-10 relative">
        
        {/* Navigation Breadcrumb */}
        <div className="flex items-center justify-between mb-6 border-b border-white/5 pb-4">
          <div className="flex items-center gap-3">
            <Link to="/" className="w-8 h-8 rounded-lg bg-gradient-to-tr from-teal-400 to-indigo-500 flex items-center justify-center font-bold text-lg text-[#090A0F]">
              🐒
            </Link>
            <span className="font-bold tracking-wider text-xs text-slate-400 uppercase">
              CYBER MONKEY &nbsp;/&nbsp; <Link to="/pentest/assessments" className="hover:text-white">ASSESSMENTS</Link> &nbsp;/&nbsp; <span className="text-white font-mono">{assessment.name}</span>
            </span>
          </div>
          <button 
            onClick={() => navigate('/pentest/assessments')}
            className="text-xs text-teal-400 hover:underline"
          >
            Back to Assessments List
          </button>
        </div>

        {/* PROMINENT ASSESSMENT NAME HEADER (FIXED AT TOP ACROSS ALL TABS) */}
        <div className="mb-6 pb-6 border-b border-white/5 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <h1 className="text-3xl md:text-4xl font-black text-slate-100 tracking-tight">
                {assessment.name}
              </h1>
              {getStatusBadge(assessment.status)}
            </div>
            <p className="text-sm text-slate-400 font-medium">
              {assessment.organization ? `${assessment.organization} • ` : ''}
              <span className="text-teal-300 font-semibold">{assessment.assessment_type}</span> Assessment
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsEditing(true)}
              className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-white/10 hover:bg-white/20 text-slate-200 border border-white/10 transition-all cursor-pointer"
            >
              Edit Assessment
            </button>
            <button
              id="btn_delete_assessment"
              onClick={() => setShowDeleteModal(true)}
              className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition-all cursor-pointer"
            >
              Delete
            </button>
          </div>
        </div>

        {/* ASSESSMENT MODULE NAVIGATION TABS */}
        {!isEditing && (
          <div className="flex items-center gap-1 border-b border-white/5 mb-8 overflow-x-auto pb-1 scrollbar-none">
            {tabs.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => handleTabClick(tab)}
                  className={`py-3 px-4 text-xs font-bold whitespace-nowrap border-b-2 transition-all cursor-pointer rounded-t-lg ${
                    isActive
                      ? 'border-teal-400 text-teal-300 bg-white/5'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-white/[0.02]'
                  }`}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>
        )}

        {/* TAB CONTENTS (RENDERED BELOW PROMINENT HEADER & TABS) */}
        {!isEditing ? (
          activeTab === 'overview' ? (
            <div className="space-y-6">
              {/* Overview Summary Box */}
              <div className="p-6 rounded-2xl cyber-glass relative overflow-hidden">
                <div className="absolute top-0 left-0 w-1.5 h-full bg-teal-400"></div>
                <h2 className="text-lg font-bold mb-4 border-b border-white/5 pb-2 text-slate-200">
                  Assessment Overview
                </h2>
                
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 text-sm mb-6">
                  <div>
                    <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Organization</span>
                    <span className="font-semibold text-slate-200">{assessment.organization || '—'}</span>
                  </div>
                  <div>
                    <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Assessment Type</span>
                    <span className="font-semibold text-slate-200">{assessment.assessment_type}</span>
                  </div>
                  <div>
                    <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Status</span>
                    <div className="mt-1">{getStatusBadge(assessment.status)}</div>
                  </div>
                  <div>
                    <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Scope Targets</span>
                    <span className="font-mono text-teal-400 font-bold text-base">{assessment.target_count}</span>
                  </div>
                  <div>
                    <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Start Date</span>
                    <span className="font-mono text-slate-300">{assessment.start_date || '—'}</span>
                  </div>
                  <div>
                    <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">End Date</span>
                    <span className="font-mono text-slate-300">{assessment.end_date || '—'}</span>
                  </div>
                </div>

                {assessment.description && (
                  <div className="border-t border-white/5 pt-4">
                    <span className="block text-xs text-slate-500 uppercase tracking-wider mb-2">Description</span>
                    <p className="text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">{assessment.description}</p>
                  </div>
                )}
              </div>

              {/* Target Scoping Manager */}
              <div className="p-6 rounded-2xl cyber-glass">
                <TargetManager 
                  assessmentId={assessmentId} 
                  assessment={assessment}
                  onTargetCountChange={fetchDetails} 
                />
              </div>
            </div>
          ) : activeTab === 'reconnaissance' ? (
            <div className="p-6 rounded-2xl cyber-glass">
              <ReconManager assessmentId={assessmentId} />
            </div>
          ) : activeTab === 'network-scanning' ? (
            <div className="p-6 rounded-2xl cyber-glass">
              <div className="mb-6 pb-4 border-b border-white/5">
                <h2 className="text-xl font-bold text-slate-100 mb-1">Network Scanning Workspace</h2>
                <p className="text-xs text-slate-400">Scoped Network Port & Service Discovery for {assessment.name}</p>
              </div>
              <ReconManager assessmentId={assessmentId} />
            </div>
          ) : activeTab === 'web-testing' ? (
            <div className="p-6 rounded-2xl cyber-glass">
              <div className="mb-6 pb-4 border-b border-white/5">
                <h2 className="text-xl font-bold text-slate-100 mb-1">Web Application Testing Workspace</h2>
                <p className="text-xs text-slate-400">Nikto Web Server & API Security Assessment for {assessment.name}</p>
              </div>
              <VulnerabilityManager assessmentId={assessmentId} />
            </div>
          ) : activeTab === 'vulnerabilities' ? (
            <div className="p-6 rounded-2xl cyber-glass">
              <VulnerabilityManager assessmentId={assessmentId} />
            </div>
          ) : activeTab === 'findings' ? (
            <div className="p-6 rounded-2xl cyber-glass text-center py-16">
              <div className="text-4xl mb-3">🪲</div>
              <h3 className="text-lg font-bold mb-1 text-slate-200">Assessment Findings Directory</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Consolidated vulnerabilities and findings for <strong className="text-teal-300">{assessment.name}</strong> will be cataloged here.
              </p>
            </div>
          ) : activeTab === 'ai-analysis' ? (
            <div className="p-6 rounded-2xl cyber-glass text-center py-16">
              <div className="text-4xl mb-3">🧠</div>
              <h3 className="text-lg font-bold mb-1 text-slate-200">AI Security Analysis Workspace</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Secure AI log & vulnerability pattern intelligence analysis for <strong className="text-teal-300">{assessment.name}</strong>.
              </p>
            </div>
          ) : activeTab === 'reports' ? (
            <div className="p-6 rounded-2xl cyber-glass text-center py-16">
              <div className="text-4xl mb-3">📄</div>
              <h3 className="text-lg font-bold mb-1 text-slate-200">Penetration Test Report Generator</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Generate executive summary and technical penetration test reports for <strong className="text-teal-300">{assessment.name}</strong>.
              </p>
            </div>
          ) : null
        ) : (
          /* Edit Assessment View */
          <div className="p-6 rounded-2xl cyber-glass border border-white/5 max-w-2xl mx-auto">
            <h2 className="text-xl font-bold mb-6 border-b border-white/5 pb-3">Edit Assessment Details</h2>
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-1">
                  Assessment Name <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  name="name"
                  value={editForm.name}
                  onChange={handleEditChange}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white text-sm focus:outline-none focus:border-teal-400"
                />
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-1">Organization</label>
                <input
                  type="text"
                  name="organization"
                  value={editForm.organization}
                  onChange={handleEditChange}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white text-sm focus:outline-none focus:border-teal-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-1">Assessment Type</label>
                  <select
                    name="assessment_type"
                    value={editForm.assessment_type}
                    onChange={handleEditChange}
                    className="w-full px-3 py-2 rounded-lg bg-[#0F111A] border border-white/10 text-white text-sm focus:outline-none focus:border-teal-400"
                  >
                    {types.map(t => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-1">Status</label>
                  <select
                    name="status"
                    value={editForm.status}
                    onChange={handleEditChange}
                    className="w-full px-3 py-2 rounded-lg bg-[#0F111A] border border-white/10 text-white text-sm focus:outline-none focus:border-teal-400"
                  >
                    {statuses.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
                  </select>
                </div>
              </div>

              {editError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs">
                  {editError}
                </div>
              )}

              <div className="flex justify-end gap-3 pt-4 border-t border-white/5">
                <button
                  type="button"
                  onClick={() => setIsEditing(false)}
                  className="px-4 py-2 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 text-slate-300 text-xs font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={editLoading}
                  className="px-5 py-2 rounded-lg bg-teal-400 hover:bg-teal-300 text-[#090A0F] text-xs font-bold"
                >
                  {editLoading ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>
        )}

      </div>
    </div>
  );
};

export default AssessmentWorkspace;
