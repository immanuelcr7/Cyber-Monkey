import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { createAssessment } from '../services/api';

const CreateAssessment = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: '',
    organization: '',
    assessment_type: 'Web Application', // Default select option
    description: '',
    start_date: '',
    end_date: '',
    status: 'active'
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const types = [
    'External Network',
    'Internal Network',
    'Web Application',
    'API',
    'Cloud',
    'Other'
  ];

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Front-end Validation
    const nameTrimmed = formData.name.trim();
    if (!nameTrimmed) {
      setError('Assessment Name is required.');
      return;
    }
    
    if (!formData.assessment_type) {
      setError('Assessment Type is required.');
      return;
    }

    if (formData.start_date && formData.end_date) {
      const start = new Date(formData.start_date);
      const end = new Date(formData.end_date);
      if (end < start) {
        setError('End Date must not be before Start Date.');
        return;
      }
    }

    try {
      setLoading(true);
      setError('');
      
      // Clean dates to send null if empty
      const payload = {
        ...formData,
        name: nameTrimmed,
        organization: formData.organization.trim() || null,
        description: formData.description.trim() || null,
        start_date: formData.start_date || null,
        end_date: formData.end_date || null
      };

      const result = await createAssessment(payload);
      if (result && result.id) {
        navigate(`/pentest/assessments/${result.id}`);
      } else {
        setError('Unable to create assessment.');
      }
    } catch (err) {
      if (!err.response) {
        // Backend unavailable
        setError('Backend connection unavailable. Please make sure the Cyber Monkey API is running.');
      } else {
        // Backend returned error
        const status = err.response.status;
        if (status === 400) {
          setError('Please check the entered information.');
        } else {
          setError('Unable to create assessment.');
        }
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen p-6 md:p-12 relative overflow-hidden bg-[#090A0F] text-slate-100">
      
      {/* Decorative gradients */}
      <div className="absolute top-[-10%] left-[-10%] w-[35%] h-[35%] rounded-full bg-indigo-500/5 blur-[120px] pointer-events-none"></div>

      <div className="max-w-xl mx-auto z-10 relative">
        
        {/* Navigation Breadcrumb */}
        <div className="flex items-center justify-between mb-8 border-b border-white/5 pb-6">
          <div className="flex items-center gap-3">
            <Link to="/" className="w-8 h-8 rounded-lg bg-gradient-to-tr from-teal-400 to-indigo-500 flex items-center justify-center font-bold text-lg text-[#090A0F]">
              🐒
            </Link>
            <span className="font-bold tracking-wider text-sm text-slate-400">
              CYBER MONKEY &nbsp;/&nbsp; <Link to="/pentest/assessments" className="hover:text-white">ASSESSMENTS</Link> &nbsp;/&nbsp; <span className="text-white">NEW</span>
            </span>
          </div>
          <Link to="/pentest/assessments" className="text-xs text-slate-400 hover:text-white">
            Cancel
          </Link>
        </div>

        {/* Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-black mb-1">Create New Assessment</h1>
          <p className="text-slate-400 text-sm">
            Define the scope and details of your security assessment.
          </p>
        </div>

        {/* Error notification */}
        {error && (
          <div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm rounded-xl mb-6">
            <strong>System Alert:</strong> {error}
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 rounded-2xl cyber-glass space-y-6">
          
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
              value={formData.name}
              onChange={handleChange}
              disabled={loading}
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
              value={formData.organization}
              onChange={handleChange}
              disabled={loading}
              className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 transition-colors"
            />
          </div>

          {/* Type dropdown */}
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Assessment Type *
            </label>
            <select
              name="assessment_type"
              value={formData.assessment_type}
              onChange={handleChange}
              disabled={loading}
              className="w-full px-4 py-2.5 rounded-lg bg-[#0F111E] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer"
            >
              {types.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
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
              value={formData.description}
              onChange={handleChange}
              disabled={loading}
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
                value={formData.start_date}
                onChange={handleChange}
                disabled={loading}
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
                value={formData.end_date}
                onChange={handleChange}
                disabled={loading}
                className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 transition-colors"
              />
            </div>
          </div>

          {/* Actions Button Grid */}
          <div className="pt-4 border-t border-white/5 flex gap-4">
            <Link
              to="/pentest/assessments"
              className="flex-1 py-3 text-center rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 font-bold text-sm transition-all duration-300"
            >
              Cancel
            </Link>
            <button
              id="btn_submit_assessment"
              type="submit"
              disabled={loading}
              className="flex-1 py-3 rounded-lg bg-teal-400 hover:bg-teal-300 text-[#090A0F] font-bold text-sm shadow-lg shadow-teal-500/10 cursor-pointer flex items-center justify-center gap-2 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading && (
                <svg className="animate-spin h-4 w-4 text-[#090A0F]" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
              )}
              {loading ? 'Creating Assessment...' : 'Create Assessment'}
            </button>
          </div>

        </form>

      </div>
    </div>
  );
};

export default CreateAssessment;

