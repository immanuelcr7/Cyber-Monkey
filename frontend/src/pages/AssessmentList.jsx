import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { getAssessments } from '../services/api';

const AssessmentList = () => {
  const [assessments, setAssessments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const fetchAssessments = async () => {
    try {
      setLoading(true);
      const data = await getAssessments();
      setAssessments(data);
      setError('');
    } catch (err) {
      setError('Backend connection unavailable. Please make sure the Cyber Monkey API is running.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssessments();
  }, []);

  const getStatusBadge = (status) => {
    const s = String(status || '').toUpperCase();
    switch (status) {
      case 'active':
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-teal-500/10 text-teal-300 border border-teal-500/20">
            {s}
          </span>
        );
      case 'completed':
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
            {s}
          </span>
        );
      case 'archived':
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-white/5 text-slate-500 border border-white/5">
            {s}
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

  return (
    <div className="min-h-screen p-6 md:p-12 relative overflow-hidden bg-[#090A0F] text-slate-100">
      
      {/* Decorative gradients */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-teal-500/5 blur-[120px] pointer-events-none"></div>

      <div className="max-w-6xl mx-auto z-10 relative">
        
        {/* Navigation Breadcrumbs */}
        <div className="flex items-center justify-between mb-8 border-b border-white/5 pb-6">
          <div className="flex items-center gap-3">
            <Link to="/" className="w-8 h-8 rounded-lg bg-gradient-to-tr from-teal-400 to-indigo-500 flex items-center justify-center font-bold text-lg text-[#090A0F]">
              🐒
            </Link>
            <span className="font-bold tracking-wider text-sm text-slate-400">
              CYBER MONKEY &nbsp;/&nbsp; <Link to="/pentest" className="hover:text-white">PENTEST</Link> &nbsp;/&nbsp; <span className="text-white">ASSESSMENTS</span>
            </span>
          </div>
          <Link to="/pentest" className="text-xs text-teal-400 hover:underline">
            Back to Dashboard
          </Link>
        </div>

        {/* Page Title & CTA */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
          <div>
            <h1 className="text-3xl font-black tracking-tight mb-1">
              Penetration Testing Assessments
            </h1>
            <p className="text-slate-400 text-sm">
              Create and manage authorized security assessments.
            </p>
          </div>
          {assessments.length > 0 && (
            <button 
              id="btn_new_assessment_top"
              onClick={() => navigate('/pentest/assessments/new')}
              className="px-4 py-2 text-sm font-semibold rounded-lg bg-gradient-to-r from-teal-400 to-indigo-500 hover:from-teal-300 hover:to-indigo-400 text-[#090A0F] shadow-lg shadow-teal-500/10 cursor-pointer transition-all duration-300"
            >
              + New Assessment
            </button>
          )}
        </div>

        {/* Error State */}
        {error && (
          <div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm rounded-xl mb-6">
            <strong>System Notification:</strong> {error}
          </div>
        )}

        {/* Loading State */}
        {loading ? (
          <div className="flex flex-col items-center justify-center py-20 cyber-glass rounded-2xl border border-white/5">
            <svg className="animate-spin h-8 w-8 text-teal-400 mb-4" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <p className="text-slate-400 text-sm">Resolving assessment registry...</p>
          </div>
        ) : assessments.length === 0 ? (
          
          /* Empty State */
          <div className="flex flex-col items-center text-center py-20 px-6 cyber-glass rounded-2xl border border-dashed border-white/10">
            <div className="text-5xl mb-4">📂</div>
            <h3 className="text-xl font-bold mb-2">No assessments yet</h3>
            <p className="text-slate-400 text-sm max-w-sm mb-8">
              Create your first penetration testing assessment to begin.
            </p>
            <button 
              id="btn_create_assessment_empty"
              onClick={() => navigate('/pentest/assessments/new')}
              className="px-6 py-2.5 text-sm font-semibold rounded-lg bg-teal-400 hover:bg-teal-300 text-[#090A0F] cursor-pointer transition-all duration-300"
            >
              Create Assessment
            </button>
          </div>
        ) : (
          
          /* Cards Grid */
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {assessments.map((a) => (
              <div 
                key={a.id} 
                className="p-6 rounded-2xl cyber-glass relative overflow-hidden flex flex-col justify-between border border-white/5 hover:border-teal-500/30 hover:shadow-lg hover:shadow-teal-500/5 transition-all duration-300 group"
              >
                <div className="absolute top-0 left-0 w-1.5 h-full bg-gradient-to-b from-teal-400 to-indigo-500"></div>
                <div>
                  <h3 className="text-xl font-black mb-1 text-slate-200 group-hover:text-teal-300 transition-colors truncate" title={a.name}>
                    {a.name}
                  </h3>
                  <p className="text-slate-400 text-sm mb-4 truncate" title={a.organization || 'No Organization'}>
                    {a.organization || '—'}
                  </p>
                  
                  <div className="space-y-2 mb-6 text-sm text-slate-300">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Type:</span>
                      <span className="font-semibold">{a.assessment_type}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-500">Status:</span>
                      {getStatusBadge(a.status)}
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Targets:</span>
                      <span className="font-mono text-teal-400 font-bold">{a.target_count}</span>
                    </div>
                  </div>
                </div>

                <div className="pt-4 border-t border-white/5">
                  <div className="text-xs font-mono text-slate-400 mb-4 flex items-center justify-between">
                    <span>{a.start_date || '—'}</span>
                    <span className="text-slate-600">&rarr;</span>
                    <span>{a.end_date || '—'}</span>
                  </div>
                  <button 
                    onClick={() => navigate(`/pentest/assessments/${a.id}`)}
                    className="w-full py-2.5 text-xs font-bold rounded-lg bg-teal-400 hover:bg-teal-300 text-[#090A0F] cursor-pointer transition-all duration-300 text-center block shadow-sm shadow-teal-500/5"
                  >
                    Open Assessment
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

      </div>
    </div>
  );
};

export default AssessmentList;

