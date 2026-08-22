import React, { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { getAssessment, updateAssessment, deleteAssessment } from '../services/api';
import TargetManager from '../components/TargetManager';
import ReconManager from '../components/ReconManager';

const AssessmentWorkspace = () => {
  const { assessmentId } = useParams();
  const navigate = useNavigate();

  const [assessment, setAssessment] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notFound, setNotFound] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [activeTab, setActiveTab] = useState('overview'); // overview, recon

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

    if (editForm.start_date && editForm.end_date) {
      const start = new Date(editForm.start_date);
      const end = new Date(editForm.end_date);
      if (end < start) {
        setEditError('End Date must not be before Start Date.');
        return;
      }
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
      if (!err.response) {
        setEditError('Backend connection unavailable. Please make sure the Cyber Monkey API is running.');
      } else {
        setEditError('Unable to update assessment.');
      }
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
      if (!err.response) {
        setError('Backend connection unavailable. Please make sure the Cyber Monkey API is running.');
      } else {
        setError('Unable to delete assessment.');
      }
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

  const formatDate = (dateStr) => {
    if (!dateStr) return '—';
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return dateStr;
      return d.toLocaleDateString('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric'
      });
    } catch (e) {
      return dateStr;
    }
  };

  if (loading && !showDeleteModal) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-[#090A0F] text-slate-100">
        <svg className="animate-spin h-8 w-8 text-teal-400 mb-4" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        <p className="text-slate-400 text-sm">Opening secure workspace environment...</p>
      </div>
    );
  }

  if (notFound) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-[#090A0F] text-slate-100">
        <div className="p-8 max-w-md w-full text-center cyber-glass rounded-2xl border border-rose-500/20 bg-rose-500/5">
          <div className="text-5xl mb-4">⚠️</div>
          <h3 className="text-2xl font-black mb-2 text-rose-400">Assessment Not Found</h3>
          <p className="text-slate-400 text-sm mb-8">
            The requested assessment could not be found.
          </p>
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

  if (error || !assessment) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-[#090A0F] text-slate-100">
        <div className="p-6 max-w-md w-full text-center cyber-glass rounded-2xl border border-rose-500/20 bg-rose-500/5">
          <div className="text-4xl mb-4">⚠️</div>
          <h3 className="text-xl font-bold mb-2">Workspace Error</h3>
          <p className="text-slate-400 text-sm mb-6">{error || 'Assessment not found'}</p>
          <button 
            onClick={() => navigate('/pentest/assessments')} 
            className="px-4 py-2 bg-white/5 border border-white/10 hover:bg-white/10 rounded-lg text-slate-200 text-sm"
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

      <div className="max-w-4xl mx-auto z-10 relative">
        
        {/* Navigation Breadcrumb */}
        <div className="flex items-center justify-between mb-8 border-b border-white/5 pb-6">
          <div className="flex items-center gap-3">
            <Link to="/" className="w-8 h-8 rounded-lg bg-gradient-to-tr from-teal-400 to-indigo-500 flex items-center justify-center font-bold text-lg text-[#090A0F]">
              🐒
            </Link>
            <span className="font-bold tracking-wider text-sm text-slate-400">
              CYBER MONKEY &nbsp;/&nbsp; <Link to="/pentest/assessments" className="hover:text-white">ASSESSMENTS</Link> &nbsp;/&nbsp; <span className="text-white">DETAILS</span>
            </span>
          </div>
          <button 
            onClick={() => navigate('/pentest/assessments')}
            className="text-xs text-teal-400 hover:underline"
          >
            Back to Assessments
          </button>
        </div>

        {/* Workspace Tab Selector */}
        {!isEditing && (
          <div className="flex gap-2 border-b border-white/5 mb-8">
            <button
              onClick={() => setActiveTab('overview')}
              className={`pb-3 px-4 text-xs tracking-wider uppercase font-bold border-b-2 transition-all cursor-pointer ${
                activeTab === 'overview'
                  ? 'border-teal-400 text-teal-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              🎯 Targets Scoping
            </button>
            <button
              onClick={() => setActiveTab('recon')}
              className={`pb-3 px-4 text-xs tracking-wider uppercase font-bold border-b-2 transition-all cursor-pointer ${
                activeTab === 'recon'
                  ? 'border-teal-400 text-teal-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              🔍 Reconnaissance
            </button>
          </div>
        )}

        {/* View / Edit Views */}
        {!isEditing ? (
          activeTab === 'overview' ? (
            <div className="space-y-6">
              
              {/* Header Meta Block */}
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                  <h1 className="text-3xl font-black mb-1">{assessment.name}</h1>
                  <p className="text-slate-400 text-sm font-semibold">{assessment.organization || '—'}</p>
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={() => setIsEditing(true)}
                    className="px-4 py-2 text-xs font-semibold rounded bg-teal-400 hover:bg-teal-300 text-[#090A0F] transition-all cursor-pointer"
                  >
                    Edit Assessment
                  </button>
                  <button
                    id="btn_delete_assessment"
                    onClick={() => setShowDeleteModal(true)}
                    className="px-4 py-2 text-xs font-semibold rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition-all cursor-pointer"
                  >
                    Delete Assessment
                  </button>
                </div>
              </div>

              {/* Assessment Overview Section */}
              <div className="p-6 rounded-2xl cyber-glass relative overflow-hidden">
                <div className="absolute top-0 left-0 w-1.5 h-full bg-teal-400"></div>
                <h2 className="text-lg font-bold mb-4 border-b border-white/5 pb-2 text-slate-200">Assessment Overview</h2>
                
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
                    <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Targets</span>
                    <span className="font-mono text-teal-400 font-bold text-base">{assessment.target_count}</span>
                  </div>
                  <div>
                    <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Start Date</span>
                    <span className="font-mono text-slate-300">{formatDate(assessment.start_date)}</span>
                  </div>
                  <div>
                    <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">End Date</span>
                    <span className="font-mono text-slate-300">{formatDate(assessment.end_date)}</span>
                  </div>
                  <div>
                    <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Created Date</span>
                    <span className="font-mono text-slate-300">{formatDate(assessment.created_at)}</span>
                  </div>
                </div>

                <div className="border-t border-white/5 pt-4">
                  <span className="block text-xs text-slate-500 uppercase tracking-wider mb-2">Description</span>
                  <p className="text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">
                    {assessment.description || 'No description provided for this assessment configuration.'}
                  </p>
                </div>
              </div>

              {/* Targets Section */}
              <div className="p-6 rounded-2xl cyber-glass text-left">
                <TargetManager 
                  assessmentId={assessmentId} 
                  assessment={assessment}
                  onTargetCountChange={fetchDetails} 
                />
              </div>

            </div>
          ) : (
            <ReconManager assessmentId={assessmentId} assessment={assessment} />
          )
        ) : (
          
          /* Edit Assessment Form */
          <div className="space-y-6">
            <div>
              <h1 className="text-2xl font-black mb-1">Edit Assessment</h1>
              <p className="text-slate-400 text-sm">Update the metadata and parameters of this assessment.</p>
            </div>

            {editError && (
              <div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm rounded-xl">
                <strong>Update Alert:</strong> {editError}
              </div>
            )}

            <form onSubmit={handleEditSubmit} className="p-6 rounded-2xl cyber-glass space-y-6">
              
              {/* Assessment Name */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Assessment Name *
                </label>
                <input
                  type="text"
                  name="name"
                  required
                  placeholder="e.g. ACME External Security Assessment"
                  value={editForm.name}
                  onChange={handleEditChange}
                  disabled={editLoading}
                  className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 transition-colors"
                />
              </div>

              {/* Organization */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Organization
                </label>
                <input
                  type="text"
                  name="organization"
                  placeholder="e.g. ACME Technologies"
                  value={editForm.organization}
                  onChange={handleEditChange}
                  disabled={editLoading}
                  className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 transition-colors"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                {/* Type dropdown */}
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Assessment Type *
                  </label>
                  <select
                    name="assessment_type"
                    value={editForm.assessment_type}
                    onChange={handleEditChange}
                    disabled={editLoading}
                    className="w-full px-4 py-2.5 rounded-lg bg-[#0F111E] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer"
                  >
                    {types.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>

                {/* Status dropdown */}
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Status *
                  </label>
                  <select
                    name="status"
                    value={editForm.status}
                    onChange={handleEditChange}
                    disabled={editLoading}
                    className="w-full px-4 py-2.5 rounded-lg bg-[#0F111E] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer"
                  >
                    {statuses.map((s) => (
                      <option key={s.value} value={s.value}>{s.label}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Description */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Description
                </label>
                <textarea
                  name="description"
                  rows="3"
                  placeholder="Provide a brief summary of scope guidelines or authorization details."
                  value={editForm.description}
                  onChange={handleEditChange}
                  disabled={editLoading}
                  className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 transition-colors resize-none"
                />
              </div>

              {/* Dates Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Start Date
                  </label>
                  <input
                    type="date"
                    name="start_date"
                    value={editForm.start_date}
                    onChange={handleEditChange}
                    disabled={editLoading}
                    className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 transition-colors"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    End Date
                  </label>
                  <input
                    type="date"
                    name="end_date"
                    value={editForm.end_date}
                    onChange={handleEditChange}
                    disabled={editLoading}
                    className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 transition-colors"
                  />
                </div>
              </div>

              {/* Actions Button Grid */}
              <div className="pt-4 border-t border-white/5 flex gap-4">
                <button
                  type="button"
                  onClick={() => {
                    setIsEditing(false);
                    setEditError('');
                  }}
                  className="flex-1 py-3 text-center rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 font-bold text-sm transition-all duration-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={editLoading}
                  className="flex-1 py-3 rounded-lg bg-teal-400 hover:bg-teal-300 text-[#090A0F] font-bold text-sm shadow-lg shadow-teal-500/10 cursor-pointer flex items-center justify-center gap-2 transition-all duration-300 disabled:opacity-50"
                >
                  {editLoading && (
                    <svg className="animate-spin h-4 w-4 text-[#090A0F]" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                  )}
                  {editLoading ? 'Saving Changes...' : 'Save Changes'}
                </button>
              </div>

            </form>
          </div>
        )}

      </div>

      {/* Delete Confirmation Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="max-w-md w-full p-6 rounded-2xl cyber-glass border border-rose-500/20 bg-[#0F111E] shadow-2xl">
            <h3 className="text-xl font-bold text-rose-400 mb-2">Delete this assessment?</h3>
            <p className="text-slate-400 text-sm mb-6 leading-relaxed">
              All associated assessment data may be removed. This action cannot be undone.
            </p>
            <div className="flex gap-4">
              <button
                onClick={() => setShowDeleteModal(false)}
                className="flex-1 py-2.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm font-semibold transition-all cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmedDelete}
                className="flex-1 py-2.5 rounded-lg bg-rose-500 hover:bg-rose-600 text-white text-sm font-semibold transition-all cursor-pointer"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

export default AssessmentWorkspace;

