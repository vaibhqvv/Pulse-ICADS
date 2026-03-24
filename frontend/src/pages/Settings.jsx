import React, { useState, useEffect } from 'react';
import { Save, RefreshCw, Trash2, Bell, BellOff, Key } from 'lucide-react';
import Layout from '../components/layout/Layout';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { getSystemConfig, updateSystemConfig } from '../firebase/alerts';
import { requestNotificationPermission } from '../firebase/messaging';
import { useAuthContext } from '../context/AuthContext';

export default function Settings() {
  const { user, changePassword } = useAuthContext();
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saveStatus, setSaveStatus] = useState(null);

  const [currentPass, setCurrentPass] = useState('');
  const [newPass, setNewPass] = useState('');
  const [confirmPass, setConfirmPass] = useState('');
  const [passError, setPassError] = useState('');
  const [passSuccess, setPassSuccess] = useState('');

  useEffect(() => {
    getSystemConfig()
      .then((data) => {
        setConfig({
          anomaly_threshold: data.anomaly_threshold ?? 0.5,
          attack_threshold: data.attack_threshold ?? 0.75,
          baseline_packets_per_sec: data.baseline_packets_per_sec ?? 100,
          contamination: data.contamination ?? 0.1,
          notification_enabled: data.notification_enabled ?? true,
          severity_filter_min: data.severity_filter_min ?? 'low',
        });
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const handleSave = async () => {
    setSaveStatus('saving');
    try {
      await updateSystemConfig(config);
      setSaveStatus('success');
      setTimeout(() => setSaveStatus(null), 3000);
    } catch (err) {
      console.error('Save failed:', err);
      setSaveStatus('error');
      setTimeout(() => setSaveStatus(null), 3000);
    }
  };

  const handleNotificationToggle = async () => {
    const newValue = !config.notification_enabled;
    if (newValue) {
      const token = await requestNotificationPermission();
      if (!token) return;
    }
    setConfig({ ...config, notification_enabled: newValue });
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setPassError('');
    setPassSuccess('');

    if (newPass !== confirmPass) {
      setPassError('Passwords do not match');
      return;
    }
    if (newPass.length < 6) {
      setPassError('Password must be at least 6 characters');
      return;
    }

    try {
      await changePassword(currentPass, newPass);
      setPassSuccess('Password updated successfully');
      setCurrentPass('');
      setNewPass('');
      setConfirmPass('');
    } catch (err) {
      setPassError(err.message);
    }
  };

  if (loading) {
    return (
      <Layout title="Settings">
        <LoadingSpinner message="Loading settings..." />
      </Layout>
    );
  }

  return (
    <Layout title="Settings">
      <div className="max-w-3xl space-y-6">
        {/* ML Model Settings */}
        <section className="card p-5">
          <h2 className="font-heading text-lg text-text-primary mb-4">ML Model Settings</h2>

          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-sm text-text-secondary">Contamination Rate</label>
                <span className="text-sm text-accent-cyan font-mono">
                  {(config.contamination * 100).toFixed(0)}%
                </span>
              </div>
              <input
                type="range"
                min="0.01"
                max="0.30"
                step="0.01"
                value={config.contamination}
                onChange={(e) => setConfig({ ...config, contamination: parseFloat(e.target.value) })}
                className="w-full accent-accent-cyan"
              />
              <div className="flex justify-between text-[10px] text-text-secondary mt-0.5">
                <span>1%</span>
                <span>30%</span>
              </div>
            </div>

            <div className="flex gap-3">
              <button className="btn-secondary flex items-center gap-2 text-sm">
                <RefreshCw className="w-4 h-4" />
                Retrain Now
              </button>
              <button className="btn-danger flex items-center gap-2 text-sm">
                <Trash2 className="w-4 h-4" />
                Reset Model
              </button>
            </div>
          </div>
        </section>

        {/* Detection Thresholds */}
        <section className="card p-5">
          <h2 className="font-heading text-lg text-text-primary mb-4">Detection Thresholds</h2>

          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-sm text-text-secondary">Anomaly Threshold</label>
                <span className="text-sm text-severity-medium font-mono">{config.anomaly_threshold}</span>
              </div>
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={config.anomaly_threshold}
                onChange={(e) => setConfig({ ...config, anomaly_threshold: parseFloat(e.target.value) })}
                className="w-full accent-severity-medium"
              />
              <p className="text-xs text-text-secondary mt-0.5">
                Scores above this are classified as "suspicious"
              </p>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-sm text-text-secondary">Attack Threshold</label>
                <span className="text-sm text-severity-critical font-mono">{config.attack_threshold}</span>
              </div>
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={config.attack_threshold}
                onChange={(e) => setConfig({ ...config, attack_threshold: parseFloat(e.target.value) })}
                className="w-full accent-severity-critical"
              />
              <p className="text-xs text-text-secondary mt-0.5">
                Scores above this are classified as "attack"
              </p>
            </div>

            <div>
              <label className="block text-sm text-text-secondary mb-1.5">Baseline Packets/sec</label>
              <input
                type="number"
                value={config.baseline_packets_per_sec}
                onChange={(e) => setConfig({ ...config, baseline_packets_per_sec: parseInt(e.target.value) || 100 })}
                className="input-dark w-40"
              />
              <p className="text-xs text-text-secondary mt-0.5">
                Used for spike detection (spike = 3× baseline)
              </p>
            </div>

            <button
              onClick={handleSave}
              disabled={saveStatus === 'saving'}
              className="btn-primary flex items-center gap-2"
            >
              <Save className="w-4 h-4" />
              {saveStatus === 'saving' ? 'Saving...' : 'Save Changes'}
            </button>

            {saveStatus === 'success' && (
              <p className="text-sm text-status-normal">Settings saved successfully</p>
            )}
            {saveStatus === 'error' && (
              <p className="text-sm text-severity-critical">Failed to save settings</p>
            )}
          </div>
        </section>

        {/* Notification Settings */}
        <section className="card p-5">
          <h2 className="font-heading text-lg text-text-primary mb-4">Notifications</h2>

          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {config.notification_enabled ? (
                  <Bell className="w-5 h-5 text-accent-blue" />
                ) : (
                  <BellOff className="w-5 h-5 text-text-secondary" />
                )}
                <div>
                  <p className="text-sm text-text-primary">Browser Push Notifications</p>
                  <p className="text-xs text-text-secondary">
                    Receive alerts for high/critical severity events
                  </p>
                </div>
              </div>
              <button
                onClick={handleNotificationToggle}
                className={`relative w-12 h-6 rounded-full transition-colors ${
                  config.notification_enabled ? 'bg-accent-blue' : 'bg-gray-300'
                }`}
              >
                <div
                  className={`absolute top-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${
                    config.notification_enabled ? 'translate-x-6' : 'translate-x-0.5'
                  }`}
                />
              </button>
            </div>

            <div>
              <label className="block text-sm text-text-secondary mb-1.5">
                Minimum Severity for Notification
              </label>
              <select
                value={config.severity_filter_min}
                onChange={(e) => setConfig({ ...config, severity_filter_min: e.target.value })}
                className="select-dark w-40"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>
        </section>

        {/* Account Section */}
        <section className="card p-5">
          <h2 className="font-heading text-lg text-text-primary mb-4">Account</h2>

          <div className="space-y-4">
            <div>
              <label className="block text-sm text-text-secondary mb-1">Email</label>
              <p className="text-sm text-text-primary font-mono">{user?.email || '—'}</p>
            </div>

            <form onSubmit={handleChangePassword} className="space-y-3">
              <h3 className="text-sm font-medium text-text-secondary flex items-center gap-2">
                <Key className="w-4 h-4" /> Change Password
              </h3>
              <input
                type="password"
                placeholder="Current password"
                value={currentPass}
                onChange={(e) => setCurrentPass(e.target.value)}
                className="input-dark w-full max-w-sm"
                required
              />
              <input
                type="password"
                placeholder="New password"
                value={newPass}
                onChange={(e) => setNewPass(e.target.value)}
                className="input-dark w-full max-w-sm"
                required
              />
              <input
                type="password"
                placeholder="Confirm new password"
                value={confirmPass}
                onChange={(e) => setConfirmPass(e.target.value)}
                className="input-dark w-full max-w-sm"
                required
              />
              {passError && <p className="text-sm text-severity-critical">{passError}</p>}
              {passSuccess && <p className="text-sm text-status-normal">{passSuccess}</p>}
              <button type="submit" className="btn-secondary text-sm">
                Update Password
              </button>
            </form>
          </div>
        </section>
      </div>
    </Layout>
  );
}
