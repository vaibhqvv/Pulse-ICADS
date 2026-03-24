import React from 'react';
import { X, Check, AlertTriangle } from 'lucide-react';
import { SeverityBadge, ClassificationBadge } from '../common/Badge';
import { formatTimestamp } from '../../utils/formatters';
import { getScoreColor, scoreToPercentage, getRiskLevel } from '../../utils/anomalyDetector';

export default function AlertCard({ alert, onClose, onAcknowledge }) {
  if (!alert) return null;

  const scoreColor = getScoreColor(alert.anomaly_score);
  const scorePercent = scoreToPercentage(alert.anomaly_score);

  return (
    <div className="fixed inset-0 bg-black/30 z-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-md border border-gray-200 shadow-lg w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-gray-200">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-severity-high" />
            <h2 className="font-heading text-lg text-text-primary">Alert Details</h2>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded text-text-secondary hover:text-text-primary hover:bg-gray-50 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 space-y-5">
          {/* Anomaly score progress bar */}
          <div className="p-4 rounded-md bg-bg-primary">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-text-secondary">Anomaly Score</span>
              <span className="text-sm font-medium font-mono" style={{ color: scoreColor }}>
                {alert.anomaly_score?.toFixed(4)} — {getRiskLevel(alert.anomaly_score)}
              </span>
            </div>
            <div className="w-full h-3 bg-bg-elevated rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${scorePercent}%`,
                  backgroundColor: scoreColor,
                }}
              />
            </div>
            <div className="flex justify-between mt-1">
              <span className="text-[10px] text-text-secondary">0.0 (Safe)</span>
              <span className="text-[10px] text-text-secondary">1.0 (Critical)</span>
            </div>
          </div>

          {/* Detail fields */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <DetailField label="Timestamp" value={formatTimestamp(alert.timestamp)} mono />
            <DetailField label="Source" value={alert.source} />
            <DetailField label="Source IP" value={alert.src_ip} mono />
            <DetailField label="Destination IP" value={alert.dest_ip} mono />
            <DetailField label="Source Port" value={alert.src_port} mono />
            <DetailField label="Destination Port" value={alert.dest_port} mono />
            <DetailField label="Protocol" value={alert.protocol} />
            <DetailField label="Alert Type" value={alert.alert_type} />
            <DetailField
              label="Severity"
              value={<SeverityBadge severity={alert.severity} />}
            />
            <DetailField
              label="Classification"
              value={<ClassificationBadge classification={alert.classification} />}
            />
            <DetailField label="Category" value={alert.category} />
            <DetailField
              label="Packet Count"
              value={Number(alert.packet_count || 0).toLocaleString()}
              mono
            />
            <DetailField
              label="Bytes"
              value={Number(alert.bytes || 0).toLocaleString()}
              mono
            />
            <DetailField
              label="Acknowledged"
              value={alert.acknowledged ? '✓ Yes' : '✗ No'}
            />
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 p-5 border-t border-gray-200">
          {!alert.acknowledged && (
            <button
              onClick={() => onAcknowledge?.(alert.id)}
              className="btn-primary flex items-center gap-2 text-sm"
            >
              <Check className="w-4 h-4" />
              Acknowledge
            </button>
          )}
          <button onClick={onClose} className="btn-secondary text-sm">
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function DetailField({ label, value, mono = false }) {
  return (
    <div>
      <p className="text-xs text-text-secondary mb-1">{label}</p>
      {typeof value === 'string' || typeof value === 'number' ? (
        <p className={`text-sm text-text-primary ${mono ? 'font-mono' : ''}`}>
          {value || '—'}
        </p>
      ) : (
        value
      )}
    </div>
  );
}
