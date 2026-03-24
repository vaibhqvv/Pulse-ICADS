import React from 'react';
import { Brain, CheckCircle, Loader2, AlertCircle } from 'lucide-react';
import { formatTimestamp } from '../../utils/formatters';

export default function ThreatMap({ liveMetrics, systemConfig }) {
  const modelStatus = liveMetrics?.model_status || 'offline';
  const trainingProgress = liveMetrics?.model_training_progress || 0;
  const isTraining = modelStatus === 'training';
  const isReady = modelStatus === 'ready';

  const contamination = systemConfig?.contamination || 0.1;
  const anomalyThreshold = systemConfig?.anomaly_threshold || 0.5;
  const attackThreshold = systemConfig?.attack_threshold || 0.75;
  const trainingSamples = systemConfig?.model_training_samples || 0;
  const lastTrained = systemConfig?.model_trained_at;

  return (
    <div className="card p-4">
      <div className="flex items-center gap-2 mb-4">
        <Brain className="w-5 h-5 text-accent-cyan" />
        <h3 className="text-sm font-medium text-text-secondary">
          ML Model Status
        </h3>
      </div>

      {/* Status indicator */}
      <div className="flex items-center gap-3 mb-4 p-3 rounded-md bg-bg-primary">
        {isReady && (
          <>
            <CheckCircle className="w-5 h-5 text-status-normal" />
            <span className="text-sm text-status-normal font-medium">Model Ready</span>
          </>
        )}
        {isTraining && (
          <>
            <Loader2 className="w-5 h-5 text-accent-blue animate-spin" />
            <span className="text-sm text-accent-blue font-medium">Training...</span>
          </>
        )}
        {!isReady && !isTraining && (
          <>
            <AlertCircle className="w-5 h-5 text-gray-400" />
            <span className="text-sm text-gray-400 font-medium">Offline</span>
          </>
        )}
      </div>

      {/* Training progress bar */}
      {isTraining && (
        <div className="mb-4">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-text-secondary">Training Progress</span>
            <span className="text-xs text-accent-blue font-medium">{trainingProgress}%</span>
          </div>
          <div className="w-full h-2 bg-bg-elevated rounded-full overflow-hidden">
            <div
              className="h-full bg-accent-blue rounded-full transition-all duration-500"
              style={{ width: `${trainingProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* Model details */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between">
          <span className="text-xs text-text-secondary">Algorithm</span>
          <span className="text-xs text-text-primary font-mono">Isolation Forest</span>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-xs text-text-secondary">Contamination</span>
          <span className="text-xs text-text-primary font-mono">
            {(contamination * 100).toFixed(0)}%
          </span>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-xs text-text-secondary">Anomaly Threshold</span>
          <span className="text-xs text-severity-medium font-mono">{anomalyThreshold}</span>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-xs text-text-secondary">Attack Threshold</span>
          <span className="text-xs text-severity-critical font-mono">{attackThreshold}</span>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-xs text-text-secondary">Training Samples</span>
          <span className="text-xs text-text-primary font-mono">
            {trainingSamples.toLocaleString()}
          </span>
        </div>

        {lastTrained && (
          <div className="flex items-center justify-between">
            <span className="text-xs text-text-secondary">Last Retrained</span>
            <span className="text-xs text-text-primary font-mono">
              {formatTimestamp(lastTrained)}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
