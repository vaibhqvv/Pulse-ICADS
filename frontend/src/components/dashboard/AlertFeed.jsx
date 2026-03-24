import React from 'react';
import { AlertTriangle } from 'lucide-react';
import { SeverityBadge, ClassificationBadge } from '../common/Badge';
import EmptyState from '../common/EmptyState';
import { formatRelativeTime } from '../../utils/formatters';

export default function AlertFeed({ alerts = [], loading = false, onAlertClick }) {
  if (loading) {
    return (
      <div className="card p-4">
        <h3 className="text-sm font-medium text-text-secondary mb-3">
          Live Feed
        </h3>
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="animate-pulse flex gap-3">
              <div className="w-14 h-5 bg-gray-100 rounded" />
              <div className="flex-1 h-5 bg-gray-100 rounded" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="card p-4">
      <h3 className="text-sm font-medium text-text-secondary mb-3">
        Live Feed
      </h3>

      {alerts.length === 0 ? (
        <EmptyState
          icon={AlertTriangle}
          title="No alerts yet"
          description="Alerts will appear here when detected."
        />
      ) : (
        <div className="space-y-0.5 max-h-[400px] overflow-y-auto pr-1">
          {alerts.map((alert, index) => (
            <div
              key={alert.id}
              onClick={() => onAlertClick?.(alert)}
              className="flex items-center gap-3 px-2.5 py-2 rounded-md cursor-pointer hover:bg-gray-50 transition-colors"
            >
              {/* Severity */}
              <SeverityBadge severity={alert.severity} />

              {/* Info */}
              <div className="flex-1 min-w-0">
                <p className="text-sm text-text-primary truncate font-medium">
                  {alert.alert_type || 'Unknown Alert'}
                </p>
                <p className="font-data text-xs text-text-secondary">
                  {alert.src_ip} → {alert.dest_ip}
                </p>
              </div>

              {/* Right */}
              <div className="flex flex-col items-end gap-1 flex-shrink-0">
                <ClassificationBadge classification={alert.classification} />
                <span className="text-[10px] text-text-secondary">
                  {formatRelativeTime(alert.timestamp)}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
