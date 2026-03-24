import React, { useState, useEffect } from 'react';
import { AlertTriangle, ShieldAlert, Activity, Wifi } from 'lucide-react';
import Layout from '../components/layout/Layout';
import StatCard from '../components/dashboard/StatCard';
import TrafficChart from '../components/dashboard/TrafficChart';
import AlertFeed from '../components/dashboard/AlertFeed';
import ThreatMap from '../components/dashboard/ThreatMap';
import ClassificationPie from '../components/analytics/ClassificationPie';
import AlertCard from '../components/alerts/AlertCard';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { useRecentAlerts, useTodayAlertCounts } from '../hooks/useAlerts';
import { useTrafficMetrics } from '../hooks/useTrafficMetrics';
import { getSystemConfig } from '../firebase/alerts';
import { formatCompact } from '../utils/formatters';
import { STATUS_COLORS, STATUS_LABELS } from '../utils/classifyAlert';

export default function Dashboard() {
  const { alerts, loading: alertsLoading } = useRecentAlerts(20);
  const { totalToday, criticalToday } = useTodayAlertCounts();
  const { liveMetrics, trafficHistory, loading: metricsLoading } = useTrafficMetrics();
  const [systemConfig, setSystemConfig] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);

  // Load system config on mount
  useEffect(() => {
    getSystemConfig().then(setSystemConfig).catch(console.error);
  }, []);

  const systemStatus = liveMetrics?.system_status || 'offline';
  const isTraining = liveMetrics?.model_status === 'training';

  return (
    <Layout title="Dashboard">
      {/* Training banner */}
      {isTraining && (
        <div className="mb-4 p-3 rounded-md bg-green-50 border border-green-200">
          <p className="text-sm text-accent-blue">
            Model training — {liveMetrics?.model_training_progress || 0}% complete.
            Classification begins after training.
          </p>
        </div>
      )}

      {/* Stat cards row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          title="Total Alerts Today"
          value={formatCompact(totalToday)}
          icon={AlertTriangle}
          color="#4A6741"
        />
        <StatCard
          title="Critical Alerts"
          value={formatCompact(criticalToday)}
          icon={ShieldAlert}
          color="#B44B4B"
        />
        <StatCard
          title="Packets / sec"
          value={formatCompact(liveMetrics?.packets_per_sec || 0)}
          icon={Activity}
          color="#8B7355"
        />
        <StatCard
          title="System Status"
          value={STATUS_LABELS[systemStatus] || 'Offline'}
          icon={Wifi}
          color={STATUS_COLORS[systemStatus] || STATUS_COLORS.offline}
          subtitle={isTraining ? `Training: ${liveMetrics?.model_training_progress || 0}%` : null}
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        <div className="lg:col-span-2">
          <TrafficChart
            data={trafficHistory}
            baseline={systemConfig?.baseline_packets_per_sec || 100}
          />
        </div>
        <ClassificationPie alerts={alerts} title="Classification (24h)" />
      </div>

      {/* Bottom row: Alert Feed + Model Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <AlertFeed
            alerts={alerts}
            loading={alertsLoading}
            onAlertClick={setSelectedAlert}
          />
        </div>
        <ThreatMap liveMetrics={liveMetrics} systemConfig={systemConfig} />
      </div>

      {/* Alert detail modal */}
      {selectedAlert && (
        <AlertCard
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
        />
      )}
    </Layout>
  );
}
