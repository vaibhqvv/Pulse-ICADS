import { useState, useEffect, useCallback, useRef } from 'react';
import {
  subscribeToAlerts,
  subscribeToRecentAlerts,
  subscribeToTodayAlertCounts,
  acknowledgeAlert,
  bulkAcknowledgeAlerts,
} from '../firebase/alerts';
import { showAlertNotification } from '../firebase/messaging';
export function useAlerts(filters = {}) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastDoc, setLastDoc] = useState(null);

  useEffect(() => {
    setLoading(true);

    const unsubscribe = subscribeToAlerts(filters, ({ alerts: newAlerts, lastDoc: newLastDoc, error: err }) => {
      if (err) {
        setError(err);
        setLoading(false);
        return;
      }
      let filtered = newAlerts;
      if (filters.searchTerm) {
        const term = filters.searchTerm.toLowerCase();
        filtered = newAlerts.filter(
          (a) =>
            a.src_ip?.toLowerCase().includes(term) ||
            a.dest_ip?.toLowerCase().includes(term) ||
            a.alert_type?.toLowerCase().includes(term) ||
            a.category?.toLowerCase().includes(term)
        );
      }

      setAlerts(filtered);
      setLastDoc(newLastDoc);
      setError(null);
      setLoading(false);
    });

    return () => unsubscribe();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    filters.severity,
    filters.classification,
    filters.source,
    filters.startDate?.getTime(),
    filters.endDate?.getTime(),
    filters.limitCount,
    filters.searchTerm,
  ]);

  const acknowledge = useCallback(async (alertId) => {
    try {
      await acknowledgeAlert(alertId);
    } catch (err) {
      console.error('Failed to acknowledge alert:', err);
      setError(err);
    }
  }, []);

  const bulkAcknowledge = useCallback(async (alertIds) => {
    try {
      await bulkAcknowledgeAlerts(alertIds);
    } catch (err) {
      console.error('Failed to bulk acknowledge:', err);
      setError(err);
    }
  }, []);

  return { alerts, loading, error, lastDoc, acknowledge, bulkAcknowledge };
}
export function useRecentAlerts(count = 20) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const prevAlertsRef = useRef([]);
  const notificationEnabledRef = useRef(true);

  useEffect(() => {
    const unsubscribe = subscribeToRecentAlerts(count, ({ alerts: newAlerts, error: err }) => {
      if (err) {
        setError(err);
        setLoading(false);
        return;
      }
      if (notificationEnabledRef.current && prevAlertsRef.current.length > 0) {
        const prevIds = new Set(prevAlertsRef.current.map((a) => a.id));
        const brandNew = newAlerts.filter((a) => !prevIds.has(a.id));
        brandNew.forEach((alert) => {
          if (alert.severity === 'critical' || alert.severity === 'high') {
            showAlertNotification(alert);
          }
        });
      }

      prevAlertsRef.current = newAlerts;
      setAlerts(newAlerts);
      setError(null);
      setLoading(false);
    });

    return () => unsubscribe();
  }, [count]);

  return { alerts, loading, error };
}
export function useTodayAlertCounts() {
  const [totalToday, setTotalToday] = useState(0);
  const [criticalToday, setCriticalToday] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const unsubscribe = subscribeToTodayAlertCounts(({ total, critical, error: err }) => {
      if (err) {
        setError(err);
        setLoading(false);
        return;
      }
      setTotalToday(total);
      setCriticalToday(critical);
      setError(null);
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  return { totalToday, criticalToday, loading, error };
}

export default useAlerts;
