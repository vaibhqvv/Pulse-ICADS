import React, { useState, useMemo } from 'react';
import { ChevronUp, ChevronDown, Check, Download, CheckSquare } from 'lucide-react';
import { SeverityBadge, ClassificationBadge } from '../common/Badge';
import EmptyState from '../common/EmptyState';
import { formatTimestamp } from '../../utils/formatters';
import { getScoreColor, scoreToPercentage } from '../../utils/anomalyDetector';

const PAGE_SIZE = 25;

export default function AlertTable({
  alerts = [],
  loading,
  onAlertClick,
  onAcknowledge,
  onBulkAcknowledge,
}) {
  const [sortField, setSortField] = useState('timestamp');
  const [sortDir, setSortDir] = useState('desc');
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [currentPage, setCurrentPage] = useState(0);

  const sortedAlerts = useMemo(() => {
    const sorted = [...alerts].sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];
      if (sortField === 'timestamp') {
        aVal = new Date(aVal).getTime();
        bVal = new Date(bVal).getTime();
      }
      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return sorted;
  }, [alerts, sortField, sortDir]);

  const totalPages = Math.ceil(sortedAlerts.length / PAGE_SIZE);
  const paginatedAlerts = sortedAlerts.slice(
    currentPage * PAGE_SIZE,
    (currentPage + 1) * PAGE_SIZE
  );

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const toggleSelect = (id) => {
    const next = new Set(selectedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelectedIds(next);
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === paginatedAlerts.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(paginatedAlerts.map((a) => a.id)));
    }
  };

  const handleBulkAcknowledge = () => {
    onBulkAcknowledge?.(Array.from(selectedIds));
    setSelectedIds(new Set());
  };

  const exportCSV = () => {
    const headers = [
      'Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Alert Type',
      'Severity', 'Classification', 'Anomaly Score', 'Acknowledged',
    ];
    const rows = sortedAlerts.map((a) => [
      formatTimestamp(a.timestamp),
      a.src_ip, a.dest_ip, a.protocol, a.alert_type,
      a.severity, a.classification, a.anomaly_score?.toFixed(4),
      a.acknowledged ? 'Yes' : 'No',
    ]);
    const csv = [headers, ...rows].map((r) => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `icads-alerts-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const SortIcon = ({ field }) => {
    if (sortField !== field) return <ChevronUp className="w-3 h-3 opacity-30" />;
    return sortDir === 'asc' ? (
      <ChevronUp className="w-3 h-3 text-accent-blue" />
    ) : (
      <ChevronDown className="w-3 h-3 text-accent-blue" />
    );
  };

  if (loading) {
    return (
      <div className="card p-4">
        <div className="space-y-3">
          {[...Array(8)].map((_, i) => (
            <div key={i} className="animate-pulse h-10 bg-gray-100 rounded" />
          ))}
        </div>
      </div>
    );
  }

  if (alerts.length === 0) {
    return (
      <div className="card">
        <EmptyState title="No alerts match your filters" />
      </div>
    );
  }

  return (
    <div className="card overflow-hidden">
      {/* Action bar */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200">
        <div className="flex items-center gap-3">
          <span className="text-sm text-text-secondary">
            {sortedAlerts.length} alert{sortedAlerts.length !== 1 ? 's' : ''}
          </span>
          {selectedIds.size > 0 && (
            <button
              onClick={handleBulkAcknowledge}
              className="btn-primary text-xs py-1 px-3 flex items-center gap-1"
            >
              <CheckSquare className="w-3.5 h-3.5" />
              Acknowledge ({selectedIds.size})
            </button>
          )}
        </div>
        <button
          onClick={exportCSV}
          className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5"
        >
          <Download className="w-3.5 h-3.5" />
          Export CSV
        </button>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="table-header">
            <tr>
              <th className="px-4 py-3 text-left">
                <input
                  type="checkbox"
                  checked={selectedIds.size === paginatedAlerts.length && paginatedAlerts.length > 0}
                  onChange={toggleSelectAll}
                  className="rounded"
                />
              </th>
              <th
                className="px-4 py-3 text-left cursor-pointer select-none"
                onClick={() => handleSort('timestamp')}
              >
                <span className="flex items-center gap-1">
                  Timestamp <SortIcon field="timestamp" />
                </span>
              </th>
              <th className="px-4 py-3 text-left">Source IP</th>
              <th className="px-4 py-3 text-left">Dest IP</th>
              <th className="px-4 py-3 text-left">Protocol</th>
              <th className="px-4 py-3 text-left">Alert Type</th>
              <th
                className="px-4 py-3 text-left cursor-pointer select-none"
                onClick={() => handleSort('severity')}
              >
                <span className="flex items-center gap-1">
                  Severity <SortIcon field="severity" />
                </span>
              </th>
              <th className="px-4 py-3 text-left">Classification</th>
              <th
                className="px-4 py-3 text-left cursor-pointer select-none"
                onClick={() => handleSort('anomaly_score')}
              >
                <span className="flex items-center gap-1">
                  Score <SortIcon field="anomaly_score" />
                </span>
              </th>
              <th className="px-4 py-3 text-left">Actions</th>
            </tr>
          </thead>
          <tbody>
            {paginatedAlerts.map((alert) => (
              <tr
                key={alert.id}
                className="table-row cursor-pointer"
                onClick={() => onAlertClick?.(alert)}
              >
                <td className="px-4 py-2.5" onClick={(e) => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    checked={selectedIds.has(alert.id)}
                    onChange={() => toggleSelect(alert.id)}
                    className="rounded"
                  />
                </td>
                <td className="px-4 py-2.5 font-mono text-xs whitespace-nowrap">
                  {formatTimestamp(alert.timestamp)}
                </td>
                <td className="px-4 py-2.5 font-mono text-xs">{alert.src_ip}</td>
                <td className="px-4 py-2.5 font-mono text-xs">{alert.dest_ip}</td>
                <td className="px-4 py-2.5 text-xs">{alert.protocol}</td>
                <td className="px-4 py-2.5 text-xs max-w-[200px] truncate">
                  {alert.alert_type}
                </td>
                <td className="px-4 py-2.5">
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td className="px-4 py-2.5">
                  <ClassificationBadge classification={alert.classification} />
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${scoreToPercentage(alert.anomaly_score)}%`,
                          backgroundColor: getScoreColor(alert.anomaly_score),
                        }}
                      />
                    </div>
                    <span className="text-xs font-mono text-text-secondary">
                      {alert.anomaly_score?.toFixed(2)}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-2.5" onClick={(e) => e.stopPropagation()}>
                  {alert.acknowledged ? (
                    <span className="text-xs text-status-normal flex items-center gap-1">
                      <Check className="w-3.5 h-3.5" /> Ack
                    </span>
                  ) : (
                    <button
                      onClick={() => onAcknowledge?.(alert.id)}
                      className="text-xs text-accent-blue hover:text-green-800 transition-colors"
                    >
                      Acknowledge
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200">
          <span className="text-xs text-text-secondary">
            Page {currentPage + 1} of {totalPages}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setCurrentPage(Math.max(0, currentPage - 1))}
              disabled={currentPage === 0}
              className="btn-secondary text-xs py-1 px-3 disabled:opacity-50"
            >
              Previous
            </button>
            <button
              onClick={() => setCurrentPage(Math.min(totalPages - 1, currentPage + 1))}
              disabled={currentPage >= totalPages - 1}
              className="btn-secondary text-xs py-1 px-3 disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
