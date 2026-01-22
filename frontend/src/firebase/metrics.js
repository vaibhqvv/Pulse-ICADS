import { ref, onValue, off } from 'firebase/database';
import { rtdb } from './config';
export function subscribeLiveMetrics(callback) {
  const metricsRef = ref(rtdb, '/live_metrics');

  const listener = onValue(
    metricsRef,
    (snapshot) => {
      if (snapshot.exists()) {
        callback(snapshot.val());
      } else {
        callback({
          packets_per_sec: 0,
          bytes_per_sec: 0,
          active_connections: 0,
          alerts_last_minute: 0,
          current_anomaly_score: 0,
          model_status: 'offline',
          model_training_progress: 0,
          system_status: 'offline',
          last_updated: 0,
        });
      }
    },
    (error) => {
      console.error('Live metrics subscription error:', error);
      callback(null);
    }
  );
  return () => off(metricsRef, 'value', listener);
}
