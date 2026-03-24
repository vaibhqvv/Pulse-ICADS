import React, { useState, useCallback } from 'react';
import Layout from '../components/layout/Layout';
import AlertFilters from '../components/alerts/AlertFilters';
import AlertTable from '../components/alerts/AlertTable';
import AlertCard from '../components/alerts/AlertCard';
import { useAlerts } from '../hooks/useAlerts';

const DEFAULT_FILTERS = {
  severity: 'all',
  classification: 'all',
  source: 'all',
  searchTerm: '',
  startDate: null,
  endDate: null,
  limitCount: 200,  // Fetch more for client-side pagination
};

export default function Alerts() {
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const [selectedAlert, setSelectedAlert] = useState(null);

  const { alerts, loading, error, acknowledge, bulkAcknowledge } = useAlerts(filters);

  const handleClearFilters = useCallback(() => {
    setFilters(DEFAULT_FILTERS);
  }, []);

  const handleAcknowledge = useCallback(async (alertId) => {
    await acknowledge(alertId);
    // Close modal if acknowledging the currently viewed alert
    if (selectedAlert?.id === alertId) {
      setSelectedAlert((prev) => prev ? { ...prev, acknowledged: true } : null);
    }
  }, [acknowledge, selectedAlert]);

  return (
    <Layout title="Alerts">
      {/* Error banner */}
      {error && (
        <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
          <p className="text-sm text-red-400">Error loading alerts: {error.message}</p>
        </div>
      )}

      {/* Filters */}
      <AlertFilters
        filters={filters}
        onFilterChange={setFilters}
        onClear={handleClearFilters}
      />

      {/* Alert table */}
      <AlertTable
        alerts={alerts}
        loading={loading}
        onAlertClick={setSelectedAlert}
        onAcknowledge={handleAcknowledge}
        onBulkAcknowledge={bulkAcknowledge}
      />

      {/* Alert detail modal */}
      {selectedAlert && (
        <AlertCard
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onAcknowledge={handleAcknowledge}
        />
      )}
    </Layout>
  );
}
