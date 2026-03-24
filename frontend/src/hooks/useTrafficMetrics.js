import { useState, useEffect, useRef, useCallback } from 'react';
import { subscribeLiveMetrics } from '../firebase/metrics';
export function useTrafficMetrics() {
  const [liveMetrics, setLiveMetrics] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Use ref for the rolling array to avoid stale closures in the callback
  const historyRef = useRef([]);
  const MAX_POINTS = 60;  // 60 data points = ~2 minutes at 2s intervals

  useEffect(() => {
    const unsubscribe = subscribeLiveMetrics((metrics) => {
      if (metrics === null) {
        setError(new Error('Failed to subscribe to live metrics'));
        setLoading(false);
        return;
      }

      setLiveMetrics(metrics);
      setError(null);
      setLoading(false);
      const newPoint = {
        time: new Date(metrics.last_updated || Date.now()).toLocaleTimeString('en-US', {
          hour12: false,
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        }),
        packets_per_sec: metrics.packets_per_sec || 0,
        bytes_per_sec: metrics.bytes_per_sec || 0,
        anomaly_score: metrics.current_anomaly_score || 0,
        active_connections: metrics.active_connections || 0,
        timestamp: metrics.last_updated || Date.now(),
      };
      const updated = [...historyRef.current, newPoint];
      if (updated.length > MAX_POINTS) {
        updated.splice(0, updated.length - MAX_POINTS);
      }
      historyRef.current = updated;
      setTrafficHistory([...updated]);
    });

    return () => unsubscribe();
  }, []);

  return { liveMetrics, trafficHistory, loading, error };
}

export default useTrafficMetrics;
