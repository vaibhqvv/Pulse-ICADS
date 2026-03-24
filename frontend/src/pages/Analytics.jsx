import React, { useState, useEffect, useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import Layout from '../components/layout/Layout';
import TrafficTimeline from '../components/analytics/TrafficTimeline';
import AnomalyChart from '../components/analytics/AnomalyChart';
import ClassificationPie from '../components/analytics/ClassificationPie';
import StatCard from '../components/dashboard/StatCard';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { getTrafficSnapshots, getAlertsSince, getSystemConfig } from '../firebase/alerts';
import { formatCompact, formatTimestamp } from '../utils/formatters';
import { CLASSIFICATION_COLORS } from '../utils/classifyAlert';
import { AlertTriangle, TrendingUp, Activity, Brain, Target } from 'lucide-react';

const TIME_RANGES = [
  { label: '1 Hour', hours: 1 },
  { label: '6 Hours', hours: 6 },
  { label: '24 Hours', hours: 24 },
  { label: '7 Days', hours: 168 },
];

export default function Analytics() {
  const [timeRange, setTimeRange] = useState(TIME_RANGES[2]);
  const [snapshots, setSnapshots] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [systemConfig, setSystemConfig] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const since = new Date(Date.now() - timeRange.hours * 3600 * 1000);

    Promise.all([
      getTrafficSnapshots(since),
      getAlertsSince(since),
      getSystemConfig(),
    ])
      .then(([snaps, als, config]) => {
        setSnapshots(snaps);
        setAlerts(als);
        setSystemConfig(config);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [timeRange]);

  const summaryStats = useMemo(() => {
    const totalAlerts = alerts.length;
    const peakPPS = snapshots.reduce((max, s) => Math.max(max, s.packets_per_sec || 0), 0);
    const avgScore = alerts.length > 0
      ? alerts.reduce((sum, a) => sum + (a.anomaly_score || 0), 0) / alerts.length
      : 0;
    const attackCount = alerts.filter((a) => a.classification === 'attack').length;
    const attackPercent = totalAlerts > 0 ? ((attackCount / totalAlerts) * 100).toFixed(1) : 0;

    return { totalAlerts, peakPPS, avgScore, attackPercent };
  }, [alerts, snapshots]);

  const alertsByHour = useMemo(() => {
    const hourBuckets = {};
    alerts.forEach((a) => {
      const date = new Date(a.timestamp);
      const hourKey = `${date.getHours().toString().padStart(2, '0')}:00`;
      if (!hourBuckets[hourKey]) {
        hourBuckets[hourKey] = { hour: hourKey, count: 0, classifications: {} };
      }
      hourBuckets[hourKey].count++;
      const cls = a.classification || 'normal';
      hourBuckets[hourKey].classifications[cls] = (hourBuckets[hourKey].classifications[cls] || 0) + 1;
    });

    return Object.values(hourBuckets)
      .sort((a, b) => a.hour.localeCompare(b.hour))
      .map((b) => {
        const majority = Object.entries(b.classifications)
          .sort(([, a], [, b]) => b - a)[0]?.[0] || 'normal';
        return { ...b, majorityClass: majority, color: CLASSIFICATION_COLORS[majority] };
      });
  }, [alerts]);

  const topIPs = useMemo(() => {
    const ipCounts = {};
    alerts.forEach((a) => {
      const ip = a.src_ip;
      if (!ipCounts[ip]) ipCounts[ip] = { ip, count: 0, types: {} };
      ipCounts[ip].count++;
      const type = a.alert_type || 'Unknown';
      ipCounts[ip].types[type] = (ipCounts[ip].types[type] || 0) + 1;
    });

    return Object.values(ipCounts)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10)
      .map((item) => ({
        ip: item.ip,
        count: item.count,
        topType: Object.entries(item.types).sort(([, a], [, b]) => b - a)[0]?.[0] || 'N/A',
      }));
  }, [alerts]);

  if (loading) {
    return (
      <Layout title="Analytics">
        <LoadingSpinner message="Loading analytics data..." />
      </Layout>
    );
  }

  return (
    <Layout title="Analytics">
      {/* Time range selector */}
      <div className="flex gap-2 mb-6 flex-wrap">
        {TIME_RANGES.map((range) => (
          <button
            key={range.label}
            onClick={() => setTimeRange(range)}
            className={`px-4 py-2 rounded-md text-sm transition-colors ${
              timeRange.label === range.label
                ? 'bg-accent-blue text-white'
                : 'bg-white text-text-secondary hover:text-text-primary border border-gray-200'
            }`}
          >
            {range.label}
          </button>
        ))}
      </div>

      {/* Summary stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard title="Total Alerts" value={formatCompact(summaryStats.totalAlerts)} icon={AlertTriangle} color="#4A6741" />
        <StatCard title="Peak PPS" value={formatCompact(summaryStats.peakPPS)} icon={TrendingUp} color="#8B7355" />
        <StatCard title="Avg Anomaly Score" value={summaryStats.avgScore.toFixed(3)} icon={Activity} color="#B8963E" />
        <StatCard title="Attack %" value={`${summaryStats.attackPercent}%`} icon={Target} color="#B44B4B" />
      </div>

      {/* Charts row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        <TrafficTimeline data={snapshots} baseline={systemConfig?.baseline_packets_per_sec || 100} />
        <AnomalyChart
          data={snapshots}
          anomalyThreshold={systemConfig?.anomaly_threshold || 0.5}
          attackThreshold={systemConfig?.attack_threshold || 0.75}
        />
      </div>

      {/* Charts row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        <div className="card p-4">
          <h3 className="text-sm font-medium text-text-secondary mb-3">
            Alert Frequency by Hour
          </h3>
          {alertsByHour.length === 0 ? (
            <div className="h-[250px] flex items-center justify-center text-text-secondary text-sm">
              No alerts in this period
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={alertsByHour} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5E2DD" />
                <XAxis dataKey="hour" tick={{ fill: '#7A756E', fontSize: 10 }} />
                <YAxis tick={{ fill: '#7A756E', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#FFFFFF', border: '1px solid #E5E2DD', borderRadius: '6px', color: '#2D2A26', fontSize: '12px' }}
                />
                <Bar dataKey="count" name="Alerts" radius={[3, 3, 0, 0]}>
                  {alertsByHour.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <ClassificationPie alerts={alerts} title="Classification Distribution" />
      </div>

      {/* Top Attacking IPs + ML Insights */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card p-4">
          <h3 className="text-sm font-medium text-text-secondary mb-3">
            Top Attacking Source IPs
          </h3>
          {topIPs.length === 0 ? (
            <div className="py-8 text-center text-text-secondary text-sm">No attack data</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="table-header">
                  <tr>
                    <th className="px-3 py-2 text-left">#</th>
                    <th className="px-3 py-2 text-left">IP Address</th>
                    <th className="px-3 py-2 text-left">Alert Count</th>
                    <th className="px-3 py-2 text-left">Most Common Type</th>
                  </tr>
                </thead>
                <tbody>
                  {topIPs.map((item, i) => (
                    <tr key={item.ip} className="table-row">
                      <td className="px-3 py-2 text-text-secondary">{i + 1}</td>
                      <td className="px-3 py-2 font-mono text-xs">{item.ip}</td>
                      <td className="px-3 py-2 font-mono">{item.count}</td>
                      <td className="px-3 py-2 text-xs truncate max-w-[200px]">{item.topType}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="card p-4">
          <div className="flex items-center gap-2 mb-4">
            <Brain className="w-5 h-5 text-accent-cyan" />
            <h3 className="text-sm font-medium text-text-secondary">
              ML Engine Insights
            </h3>
          </div>
          <div className="space-y-3">
            <InsightRow label="Algorithm" value="Isolation Forest (scikit-learn)" />
            <InsightRow label="n_estimators" value="100" />
            <InsightRow label="Contamination" value={`${((systemConfig?.contamination || 0.1) * 100).toFixed(0)}%`} />
            <InsightRow label="Training Samples" value={systemConfig?.model_training_samples?.toLocaleString() || '—'} />
            <InsightRow label="Last Retrained" value={systemConfig?.model_trained_at ? formatTimestamp(systemConfig.model_trained_at) : '—'} />

            <div className="h-px bg-gray-200 my-3" />
            <p className="text-xs text-text-secondary font-medium mb-2">Classification Distribution</p>
            {['normal', 'suspicious', 'attack'].map((cls) => {
              const count = alerts.filter((a) => a.classification === cls).length;
              const pct = alerts.length > 0 ? ((count / alerts.length) * 100).toFixed(1) : 0;
              const acknowledged = alerts.filter((a) => a.classification === cls && a.acknowledged).length;
              return (
                <div key={cls} className="flex items-center justify-between text-xs">
                  <span className="capitalize" style={{ color: CLASSIFICATION_COLORS[cls] }}>
                    {cls}
                  </span>
                  <span className="text-text-secondary">
                    {count} ({pct}%) — {acknowledged} acknowledged
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </Layout>
  );
}

function InsightRow({ label, value }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-text-secondary">{label}</span>
      <span className="text-text-primary font-mono text-xs">{value}</span>
    </div>
  );
}
