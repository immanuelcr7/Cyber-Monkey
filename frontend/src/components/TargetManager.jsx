import React, { useEffect, useState, useCallback } from 'react';
import { getTargets, createTarget, updateTarget, deleteTarget } from '../services/api';

const TargetManager = ({ assessmentId, assessment, onTargetCountChange }) => {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Modals visibility states
  const [showAddModal, setShowAddModal] = useState(false);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);

  // Selected Target state (for details, edit, delete)
  const [selectedTarget, setSelectedTarget] = useState(null);

  // Form States (Add Target)
  const [addForm, setAddForm] = useState({
    target_type: 'Domain',
    target_value: '',
    scope_status: 'in_scope',
    authorization_confirmed: false,
    description: '',
    notes: ''
  });
  const [addError, setAddError] = useState('');
  const [addLoading, setAddLoading] = useState(false);

  // Form States (Edit Target)
  const [editForm, setEditForm] = useState({
    target_type: 'Domain',
    target_value: '',
    scope_status: 'in_scope',
    authorization_confirmed: false,
    description: '',
    notes: ''
  });
  const [editError, setEditError] = useState('');
  const [editLoading, setEditLoading] = useState(false);

  // Delete Action states
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [deleteError, setDeleteError] = useState('');

  // Load Targets list
  const loadTargets = useCallback(async () => {
    try {
      setLoading(true);
      setError('');
      const data = await getTargets(assessmentId);
      setTargets(data);
    } catch (err) {
      if (!err.response) {
        setError('Backend connection unavailable. Please make sure the Cyber Monkey API is running.');
      } else {
        setError('Unable to load assessment targets.');
      }
    } finally {
      setLoading(false);
    }
  }, [assessmentId]);

  useEffect(() => {
    if (assessmentId) {
      loadTargets();
    }
  }, [assessmentId, loadTargets]);

  // Utility to format date
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
    } catch (err) {
      console.warn('Error formatting date:', err);
      return dateStr;
    }
  };

  // Check validation rules locally before backend submission to show helpful user errors
  const validateInputs = (form, setErrorCallback) => {
    const val = form.target_value.trim();
    if (!val) {
      setErrorCallback('Target Value is required.');
      return false;
    }

    if (form.target_type === 'Domain') {
      // Basic domain check
      const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
      if (!domainRegex.test(val)) {
        setErrorCallback('Invalid Target Value. Please provide a valid domain name syntax (e.g. example.com).');
        return false;
      }
    } else if (form.target_type === 'IP Address') {
      // Basic IPv4 & IPv6 checks
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
      if (!ipv4Regex.test(val) && !ipv6Regex.test(val)) {
        setErrorCallback('Invalid Target Value. Please provide a valid IPv4 or IPv6 address format (e.g. 192.168.1.1).');
        return false;
      }
    } else if (form.target_type === 'URL') {
      const urlRegex = /^https?:\/\/[^\s$.?#].[^\s]*$/i;
      if (!urlRegex.test(val)) {
        setErrorCallback('Invalid Target Value. Please provide a valid http/https URL format (e.g. https://example.com).');
        return false;
      }
    }

    if (form.scope_status === 'in_scope' && !form.authorization_confirmed) {
      setErrorCallback('Authorization confirmation is required for an in-scope target.');
      return false;
    }

    return true;
  };

  // Submit new target
  const handleAddSubmit = async (e) => {
    e.preventDefault();
    setAddError('');

    if (!validateInputs(addForm, setAddError)) {
      return;
    }

    try {
      setAddLoading(true);
      const payload = {
        target_type: addForm.target_type,
        target_value: addForm.target_value.trim(),
        scope_status: addForm.scope_status,
        authorization_confirmed: addForm.scope_status === 'in_scope' ? addForm.authorization_confirmed : false,
        description: addForm.description.trim() || null,
        notes: addForm.notes.trim() || null
      };

      await createTarget(assessmentId, payload);
      
      // Reset form
      setAddForm({
        target_type: 'Domain',
        target_value: '',
        scope_status: 'in_scope',
        authorization_confirmed: false,
        description: '',
        notes: ''
      });
      setShowAddModal(false);
      await loadTargets();
      if (onTargetCountChange) onTargetCountChange();
    } catch (err) {
      if (!err.response) {
        setAddError('Backend connection unavailable. Please make sure the Cyber Monkey API is running.');
      } else {
        setAddError(err.response?.data?.detail || 'Unable to add target.');
      }
    } finally {
      setAddLoading(false);
    }
  };

  // Edit action open
  const openEditModal = (target) => {
    setEditForm({
      target_type: target.target_type,
      target_value: target.target_value,
      scope_status: target.scope_status,
      authorization_confirmed: target.authorization_confirmed,
      description: target.description || '',
      notes: target.notes || ''
    });
    setSelectedTarget(target);
    setEditError('');
    setShowDetailModal(false);
    setShowEditModal(true);
  };

  // Submit update target
  const handleEditSubmit = async (e) => {
    e.preventDefault();
    setEditError('');

    if (!validateInputs(editForm, setEditError)) {
      return;
    }

    try {
      setEditLoading(true);
      const payload = {
        target_type: editForm.target_type,
        target_value: editForm.target_value.trim(),
        scope_status: editForm.scope_status,
        authorization_confirmed: editForm.scope_status === 'in_scope' ? editForm.authorization_confirmed : false,
        description: editForm.description.trim() || null,
        notes: editForm.notes.trim() || null
      };

      const updated = await updateTarget(selectedTarget.id, payload);
      setShowEditModal(false);
      
      // Re-load targets and refresh details if active target was open
      await loadTargets();
      if (onTargetCountChange) onTargetCountChange();
      
      // Update selected target details and show modal again
      setSelectedTarget(updated);
      setShowDetailModal(true);
    } catch (err) {
      if (!err.response) {
        setEditError('Backend connection unavailable. Please make sure the Cyber Monkey API is running.');
      } else {
        setEditError(err.response?.data?.detail || 'Unable to update target.');
      }
    } finally {
      setEditLoading(false);
    }
  };

  // Delete Action Confirm
  const openDeleteModal = (target) => {
    setSelectedTarget(target);
    setDeleteError('');
    setShowDetailModal(false);
    setShowDeleteModal(true);
  };

  const handleConfirmedDelete = async () => {
    if (deleteLoading) return;
    try {
      setDeleteLoading(true);
      setDeleteError('');
      await deleteTarget(selectedTarget.id);
      setShowDeleteModal(false);
      setSelectedTarget(null);
      await loadTargets();
      if (onTargetCountChange) onTargetCountChange();
    } catch (err) {
      if (!err.response) {
        setDeleteError('Backend connection unavailable. Please make sure the Cyber Monkey API is running.');
      } else {
        setDeleteError(err.response?.data?.detail || 'Unable to delete target.');
      }
    } finally {
      setDeleteLoading(false);
    }
  };

  // Detail view open
  const openDetailModal = (target) => {
    setSelectedTarget(target);
    setShowDetailModal(true);
  };

  // Badges rendering helper
  const renderScopeBadge = (status) => {
    if (status === 'in_scope') {
      return (
        <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-teal-500/10 text-teal-300 border border-teal-500/20 uppercase tracking-wider">
          IN SCOPE
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-purple-500/10 text-purple-300 border border-purple-500/20 uppercase tracking-wider font-semibold">
        OUT OF SCOPE
      </span>
    );
  };

  const renderAuthBadge = (confirmed, scope) => {
    if (scope === 'in_scope' && confirmed) {
      return (
        <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 uppercase tracking-wider">
          AUTHORIZED
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-rose-500/10 text-rose-300 border border-rose-500/20 uppercase tracking-wider font-semibold">
        NOT AUTHORIZED
      </span>
    );
  };

  return (
    <div className="space-y-6">
      
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-white/5 pb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-200">Assessment Targets</h2>
          <p className="text-slate-400 text-xs mt-1">
            Manage the assets authorized for this security assessment.
          </p>
        </div>
        <button
          onClick={() => {
            setAddError('');
            setShowAddModal(true);
          }}
          className="px-4 py-2.5 text-xs font-bold rounded-lg bg-teal-400 hover:bg-teal-300 text-[#090A0F] cursor-pointer flex items-center gap-1.5 transition-all shadow-md shadow-teal-400/5 self-start sm:self-auto"
        >
          <span>+</span> Add Target
        </button>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm rounded-xl">
          {error}
        </div>
      )}

      {/* Targets Loading / Empty / List State */}
      {loading ? (
        <div className="p-12 text-center flex flex-col items-center justify-center">
          <svg className="animate-spin h-6 w-6 text-teal-400 mb-3" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <span className="text-slate-500 text-xs">Loading secure target lists...</span>
        </div>
      ) : targets.length === 0 ? (
        
        /* EMPTY STATE */
        <div className="p-12 text-center cyber-glass rounded-2xl border border-white/5 flex flex-col items-center justify-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-white/5 flex items-center justify-center text-xl text-slate-400">
            🎯
          </div>
          <div>
            <h4 className="text-md font-bold text-slate-300"> No targets added </h4>
            <p className="text-slate-500 text-xs mt-1">
              Add an authorized domain, IP address, or URL to begin.
            </p>
          </div>
          <button
            onClick={() => {
              setAddError('');
              setShowAddModal(true);
            }}
            className="px-4 py-2 text-xs font-bold rounded bg-teal-400 hover:bg-teal-300 text-[#090A0F] cursor-pointer transition-all"
          >
            + Add Target
          </button>
        </div>
      ) : (
        
        /* TARGET LIST */
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {targets.map((t) => (
            <div
              key={t.id}
              onClick={() => openDetailModal(t)}
              className="p-5 rounded-2xl cyber-glass border border-white/5 hover:border-white/10 hover:bg-white/[0.02] cursor-pointer flex flex-col justify-between text-left transition-all duration-300 relative overflow-hidden group min-h-[170px]"
            >
              <div>
                <div className="flex items-start justify-between gap-3 mb-2">
                  <span className="text-base font-black text-slate-100 break-all pr-2 font-mono group-hover:text-teal-400 transition-colors">
                    {t.target_value}
                  </span>
                  <span className="text-[10px] font-mono text-slate-500 px-1.5 py-0.5 rounded bg-white/5 border border-white/10 self-start">
                    {t.target_type}
                  </span>
                </div>
                
                {/* Badges */}
                <div className="flex flex-wrap gap-2 mb-3 mt-1">
                  {renderScopeBadge(t.scope_status)}
                  {renderAuthBadge(t.authorization_confirmed, t.scope_status)}
                </div>

                <p className="text-xs text-slate-400 line-clamp-2 mt-1 pr-4 min-h-[32px]">
                  {t.description || <span className="text-slate-600 italic">No description provided</span>}
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-500">
                <span>Added: {formatDate(t.created_at)}</span>
                <span className="text-teal-500 opacity-0 group-hover:opacity-100 transition-opacity">Details &rarr;</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* -------------------- ADD TARGET MODAL -------------------- */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="max-w-lg w-full my-8 p-6 rounded-2xl cyber-glass border border-white/10 bg-[#0F111E] shadow-2xl relative">
            
            <div className="flex items-center justify-between mb-4 border-b border-white/5 pb-3">
              <h3 className="text-lg font-bold text-slate-200">Register Target Asset</h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-500 hover:text-slate-300 text-lg font-bold cursor-pointer"
              >
                &times;
              </button>
            </div>

            {addError && (
              <div className="mb-4 p-3 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs rounded-xl">
                {addError}
              </div>
            )}

            <form onSubmit={handleAddSubmit} className="space-y-4 text-left">
              
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Target Type */}
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Target Type *
                  </label>
                  <select
                    value={addForm.target_type}
                    onChange={(e) => setAddForm({ ...addForm, target_type: e.target.value })}
                    disabled={addLoading}
                    className="w-full px-3 py-2.5 rounded-lg bg-[#0A0B10] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer text-sm"
                  >
                    <option value="Domain">Domain</option>
                    <option value="IP Address">IP Address</option>
                    <option value="URL">URL</option>
                  </select>
                </div>

                {/* Scope status */}
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Scope Status *
                  </label>
                  <select
                    value={addForm.scope_status}
                    onChange={(e) => {
                      const scope = e.target.value;
                      // reset authorization confirmed checkbox if moving to out of scope
                      setAddForm({ 
                        ...addForm, 
                        scope_status: scope,
                        authorization_confirmed: scope === 'out_of_scope' ? false : addForm.authorization_confirmed 
                      });
                    }}
                    disabled={addLoading}
                    className="w-full px-3 py-2.5 rounded-lg bg-[#0A0B10] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer text-sm"
                  >
                    <option value="in_scope">In Scope</option>
                    <option value="out_of_scope">Out of Scope</option>
                  </select>
                </div>
              </div>

              {/* Target Value */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Target Value *
                </label>
                <input
                  type="text"
                  required
                  placeholder={
                    addForm.target_type === 'Domain' ? 'e.g. example.com' :
                    addForm.target_type === 'IP Address' ? 'e.g. 192.0.2.10 or 2001:db8::1' :
                    'e.g. https://example.com'
                  }
                  value={addForm.target_value}
                  onChange={(e) => setAddForm({ ...addForm, target_value: e.target.value })}
                  disabled={addLoading}
                  className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 text-sm font-mono transition-colors"
                />
                <span className="text-[10px] text-slate-500 mt-1 block">
                  Format syntax validation is enforced. No network traffic or DNS probes will be sent.
                </span>
              </div>

              {/* Description */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Description
                </label>
                <input
                  type="text"
                  placeholder="e.g. Primary web application / Client API endpoint"
                  value={addForm.description}
                  onChange={(e) => setAddForm({ ...addForm, description: e.target.value })}
                  disabled={addLoading}
                  className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 text-sm transition-colors"
                />
              </div>

              {/* Notes */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Notes
                </label>
                <textarea
                  rows="2"
                  placeholder="Optional technical notes, restrictions, or testing constraints"
                  value={addForm.notes}
                  onChange={(e) => setAddForm({ ...addForm, notes: e.target.value })}
                  disabled={addLoading}
                  className="w-full px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 text-sm transition-colors resize-none"
                />
              </div>

              {/* Authorization Checkbox */}
              <div className="p-4 rounded-xl border border-white/5 bg-white/[0.01]">
                <span className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Authorization Confirmation
                </span>
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={addForm.authorization_confirmed}
                    onChange={(e) => setAddForm({ ...addForm, authorization_confirmed: e.target.checked })}
                    disabled={addLoading || addForm.scope_status === 'out_of_scope'}
                    className="mt-1 accent-teal-400 cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
                  />
                  <span className={`text-xs leading-relaxed transition-colors ${addForm.scope_status === 'out_of_scope' ? 'text-slate-500' : 'text-slate-300'}`}>
                    I confirm that I have authorization to perform security testing against this target as part of this assessment.
                    {addForm.scope_status === 'in_scope' && <span className="text-rose-400 font-bold ml-1">*Required</span>}
                  </span>
                </label>
                {addForm.scope_status === 'out_of_scope' && (
                  <span className="text-[10px] text-purple-400 mt-2 block font-semibold">
                    Note: Out of scope targets do not require testing authorization, but cannot be authorized.
                  </span>
                )}
              </div>

              {/* Action Buttons */}
              <div className="pt-3 border-t border-white/5 flex gap-3">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="flex-1 py-2.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm font-semibold transition-all cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={addLoading}
                  className="flex-1 py-2.5 rounded-lg bg-teal-400 hover:bg-teal-300 text-[#090A0F] text-sm font-bold shadow-lg shadow-teal-500/10 flex items-center justify-center gap-1.5 transition-all disabled:opacity-50 cursor-pointer"
                >
                  {addLoading && (
                    <svg className="animate-spin h-4 w-4 text-[#090A0F]" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                  )}
                  {addLoading ? 'Adding Target...' : 'Add Target'}
                </button>
              </div>

            </form>
          </div>
        </div>
      )}

      {/* -------------------- TARGET DETAILS MODAL -------------------- */}
      {showDetailModal && selectedTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="max-w-lg w-full my-8 p-6 rounded-2xl cyber-glass border border-white/10 bg-[#0F111E] shadow-2xl relative text-left text-slate-100">
            
            <div className="flex items-center justify-between mb-4 border-b border-white/5 pb-3">
              <h3 className="text-lg font-bold text-slate-200">Target Asset Details</h3>
              <button
                onClick={() => setShowDetailModal(false)}
                className="text-slate-500 hover:text-slate-300 text-lg font-bold cursor-pointer"
              >
                &times;
              </button>
            </div>

            <div className="space-y-5 text-sm">
              
              {/* Target Value and Type */}
              <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                <span className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1 font-mono">Target Asset</span>
                <span className="text-xl font-black text-teal-400 break-all font-mono">
                  {selectedTarget.target_value}
                </span>
                <span className="block text-xs text-slate-400 mt-1 font-semibold">
                  Type: {selectedTarget.target_type}
                </span>
              </div>

              {/* Meta Grid */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Scope Status</span>
                  <div>{renderScopeBadge(selectedTarget.scope_status)}</div>
                </div>
                <div>
                  <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Authorization Status</span>
                  <div>{renderAuthBadge(selectedTarget.authorization_confirmed, selectedTarget.scope_status)}</div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-left">
                <div>
                  <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Assessment Scope</span>
                  <span className="font-semibold text-slate-200">{assessment?.name || 'Loading assessment...'}</span>
                </div>
                <div>
                  <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Created At</span>
                  <span className="font-mono text-slate-300">{formatDate(selectedTarget.created_at)}</span>
                </div>
              </div>

              {/* Status Notice */}
              <div className={`p-4 rounded-xl border ${
                selectedTarget.scope_status === 'in_scope' && selectedTarget.authorization_confirmed
                  ? 'bg-teal-500/5 border-teal-500/20 text-teal-300'
                  : 'bg-rose-500/5 border-rose-500/20 text-rose-300'
              }`}>
                <span className="block text-xs font-bold uppercase tracking-wider mb-1">Testing Authorization Status</span>
                <p className="text-xs leading-relaxed font-semibold">
                  {selectedTarget.scope_status === 'in_scope' && selectedTarget.authorization_confirmed ? (
                    'Ready for authorized security testing'
                  ) : selectedTarget.scope_status === 'out_of_scope' ? (
                    'OUT OF SCOPE - An out-of-scope target must never be considered ready for future security testing.'
                  ) : (
                    'NOT AUTHORIZED - Scope status requires authorization confirmation before testing.'
                  )}
                </p>
                {selectedTarget.scope_status === 'in_scope' && selectedTarget.authorization_confirmed && (
                  <span className="text-[10px] text-slate-400 mt-2 block font-normal leading-relaxed">
                    * Note: This status means only that the target passed Cyber Monkey's scope/authorization requirements. It does NOT mean the target has been scanned or found secure.
                  </span>
                )}
              </div>

              {/* Description */}
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Description</span>
                <p className="text-slate-300 text-sm leading-relaxed p-3 rounded-lg bg-white/[0.01] border border-white/5 min-h-[44px]">
                  {selectedTarget.description || <span className="text-slate-600 italic">No description provided</span>}
                </p>
              </div>

              {/* Notes */}
              <div>
                <span className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Technical Notes</span>
                <p className="text-slate-300 text-sm leading-relaxed p-3 rounded-lg bg-white/[0.01] border border-white/5 min-h-[44px]">
                  {selectedTarget.notes || <span className="text-slate-600 italic">No notes available</span>}
                </p>
              </div>

              {/* Actions Grid */}
              <div className="pt-4 border-t border-white/5 flex flex-col sm:flex-row gap-3">
                <button
                  onClick={() => openEditModal(selectedTarget)}
                  className="flex-1 py-2 text-center rounded-lg bg-teal-400/10 hover:bg-teal-400/20 text-teal-400 border border-teal-400/20 text-sm font-semibold transition-all cursor-pointer"
                >
                  Edit Target
                </button>
                <button
                  onClick={() => openDeleteModal(selectedTarget)}
                  className="flex-1 py-2 text-center rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 text-sm font-semibold transition-all cursor-pointer"
                >
                  Delete Target
                </button>
                <button
                  onClick={() => setShowDetailModal(false)}
                  className="flex-1 py-2 text-center rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm font-semibold transition-all cursor-pointer"
                >
                  Close
                </button>
              </div>

            </div>
          </div>
        </div>
      )}

      {/* -------------------- EDIT TARGET MODAL -------------------- */}
      {showEditModal && selectedTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="max-w-lg w-full my-8 p-6 rounded-2xl cyber-glass border border-white/10 bg-[#0F111E] shadow-2xl relative text-left">
            
            <div className="flex items-center justify-between mb-4 border-b border-white/5 pb-3">
              <h3 className="text-lg font-bold text-slate-200">Modify Target Asset</h3>
              <button
                onClick={() => {
                  setShowEditModal(false);
                  setShowDetailModal(true);
                }}
                className="text-slate-500 hover:text-slate-300 text-lg font-bold cursor-pointer"
              >
                &times;
              </button>
            </div>

            {editError && (
              <div className="mb-4 p-3 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs rounded-xl">
                {editError}
              </div>
            )}

            <form onSubmit={handleEditSubmit} className="space-y-4">
              
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Target Type */}
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Target Type *
                  </label>
                  <select
                    value={editForm.target_type}
                    onChange={(e) => setEditForm({ ...editForm, target_type: e.target.value })}
                    disabled={editLoading}
                    className="w-full px-3 py-2.5 rounded-lg bg-[#0A0B10] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer text-sm"
                  >
                    <option value="Domain">Domain</option>
                    <option value="IP Address">IP Address</option>
                    <option value="URL">URL</option>
                  </select>
                </div>

                {/* Scope status */}
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Scope Status *
                  </label>
                  <select
                    value={editForm.scope_status}
                    onChange={(e) => {
                      const scope = e.target.value;
                      setEditForm({ 
                        ...editForm, 
                        scope_status: scope,
                        authorization_confirmed: scope === 'out_of_scope' ? false : editForm.authorization_confirmed
                      });
                    }}
                    disabled={editLoading}
                    className="w-full px-3 py-2.5 rounded-lg bg-[#0A0B10] border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 transition-colors cursor-pointer text-sm"
                  >
                    <option value="in_scope">In Scope</option>
                    <option value="out_of_scope">Out of Scope</option>
                  </select>
                </div>
              </div>

              {/* Target Value */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Target Value *
                </label>
                <input
                  type="text"
                  required
                  value={editForm.target_value}
                  onChange={(e) => setEditForm({ ...editForm, target_value: e.target.value })}
                  disabled={editLoading}
                  className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 text-sm font-mono transition-colors"
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Description
                </label>
                <input
                  type="text"
                  value={editForm.description}
                  onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                  disabled={editLoading}
                  className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 text-sm transition-colors"
                />
              </div>

              {/* Notes */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Notes
                </label>
                <textarea
                  rows="2"
                  value={editForm.notes}
                  onChange={(e) => setEditForm({ ...editForm, notes: e.target.value })}
                  disabled={editLoading}
                  className="w-full px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-slate-100 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 text-sm transition-colors resize-none"
                />
              </div>

              {/* Authorization Checkbox */}
              <div className="p-4 rounded-xl border border-white/5 bg-white/[0.01]">
                <span className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Authorization Confirmation
                </span>
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={editForm.authorization_confirmed}
                    onChange={(e) => setEditForm({ ...editForm, authorization_confirmed: e.target.checked })}
                    disabled={editLoading || editForm.scope_status === 'out_of_scope'}
                    className="mt-1 accent-teal-400 cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
                  />
                  <span className={`text-xs leading-relaxed transition-colors ${editForm.scope_status === 'out_of_scope' ? 'text-slate-500' : 'text-slate-300'}`}>
                    I confirm that I have authorization to perform security testing against this target as part of this assessment.
                    {editForm.scope_status === 'in_scope' && <span className="text-rose-400 font-bold ml-1">*Required</span>}
                  </span>
                </label>
                {editForm.scope_status === 'out_of_scope' && (
                  <span className="text-[10px] text-purple-400 mt-2 block font-semibold">
                    Note: Out of scope targets do not require testing authorization, but cannot be authorized.
                  </span>
                )}
              </div>

              {/* Action Buttons */}
              <div className="pt-3 border-t border-white/5 flex gap-3">
                <button
                  type="button"
                  onClick={() => {
                    setShowEditModal(false);
                    setShowDetailModal(true);
                  }}
                  className="flex-1 py-2.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm font-semibold transition-all cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={editLoading}
                  className="flex-1 py-2.5 rounded-lg bg-teal-400 hover:bg-teal-300 text-[#090A0F] text-sm font-bold shadow-lg shadow-teal-500/10 flex items-center justify-center gap-1.5 transition-all disabled:opacity-50 cursor-pointer"
                >
                  {editLoading && (
                    <svg className="animate-spin h-4 w-4 text-[#090A0F]" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                  )}
                  {editLoading ? 'Saving...' : 'Save Changes'}
                </button>
              </div>

            </form>
          </div>
        </div>
      )}

      {/* -------------------- DELETE CONFIRMATION MODAL -------------------- */}
      {showDeleteModal && selectedTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="max-w-md w-full p-6 rounded-2xl cyber-glass border border-rose-500/20 bg-[#0F111E] shadow-2xl relative text-left">
            
            <h3 className="text-xl font-bold text-rose-400 mb-2">Delete this target?</h3>
            <p className="text-slate-400 text-sm mb-4 leading-relaxed">
              This will remove the target from this assessment.
            </p>
            
            {deleteError && (
              <div className="mb-4 p-3 bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs rounded-xl">
                {deleteError}
              </div>
            )}

            <div className="flex gap-4">
              <button
                onClick={() => {
                  setShowDeleteModal(false);
                  setShowDetailModal(true);
                }}
                disabled={deleteLoading}
                className="flex-1 py-2.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm font-semibold transition-all cursor-pointer disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmedDelete}
                disabled={deleteLoading}
                className="flex-1 py-2.5 rounded-lg bg-rose-500 hover:bg-rose-600 text-white text-sm font-bold flex items-center justify-center gap-1.5 transition-all cursor-pointer disabled:opacity-50"
              >
                {deleteLoading && (
                  <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                )}
                {deleteLoading ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

export default TargetManager;
