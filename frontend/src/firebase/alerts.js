import {
  collection,
  query,
  where,
  orderBy,
  limit,
  startAfter,
  onSnapshot,
  doc,
  updateDoc,
  getDocs,
  Timestamp,
} from 'firebase/firestore';
import { db } from './config';
export function subscribeToAlerts(filters = {}, callback) {
  const alertsRef = collection(db, 'alerts');
  const constraints = [orderBy('timestamp', 'desc')];
  if (filters.severity && filters.severity !== 'all') {
    constraints.push(where('severity', '==', filters.severity));
  }
  if (filters.classification && filters.classification !== 'all') {
    constraints.push(where('classification', '==', filters.classification));
  }
  if (filters.source && filters.source !== 'all') {
    constraints.push(where('source', '==', filters.source));
  }
  if (filters.startDate) {
    constraints.push(where('timestamp', '>=', Timestamp.fromDate(filters.startDate)));
  }
  if (filters.endDate) {
    constraints.push(where('timestamp', '<=', Timestamp.fromDate(filters.endDate)));
  }
  if (filters.lastDoc) {
    constraints.push(startAfter(filters.lastDoc));
  }

  // Limit results
  constraints.push(limit(filters.limitCount || 50));

  const q = query(alertsRef, ...constraints);

  return onSnapshot(
    q,
    (snapshot) => {
      const alerts = snapshot.docs.map((docSnap) => ({
        id: docSnap.id,
        ...docSnap.data(),
        timestamp: docSnap.data().timestamp?.toDate?.()
          ? docSnap.data().timestamp.toDate()
          : new Date(docSnap.data().timestamp),
      }));

      const lastDoc = snapshot.docs[snapshot.docs.length - 1] || null;
      callback({ alerts, lastDoc, error: null });
    },
    (error) => {
      console.error('Alert subscription error:', error);
      callback({ alerts: [], lastDoc: null, error });
    }
  );
}
export function subscribeToRecentAlerts(count = 20, callback) {
  const q = query(
    collection(db, 'alerts'),
    orderBy('timestamp', 'desc'),
    limit(count)
  );

  return onSnapshot(
    q,
    (snapshot) => {
      const alerts = snapshot.docs.map((docSnap) => ({
        id: docSnap.id,
        ...docSnap.data(),
        timestamp: docSnap.data().timestamp?.toDate?.()
          ? docSnap.data().timestamp.toDate()
          : new Date(docSnap.data().timestamp),
      }));
      callback({ alerts, error: null });
    },
    (error) => {
      console.error('Recent alerts subscription error:', error);
      callback({ alerts: [], error });
    }
  );
}
export function subscribeToTodayAlertCounts(callback) {
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);

  const q = query(
    collection(db, 'alerts'),
    where('timestamp', '>=', Timestamp.fromDate(startOfToday)),
    orderBy('timestamp', 'desc')
  );

  return onSnapshot(
    q,
    (snapshot) => {
      const total = snapshot.size;
      const critical = snapshot.docs.filter(
        (d) => d.data().severity === 'critical'
      ).length;
      callback({ total, critical, error: null });
    },
    (error) => {
      console.error('Today alert count error:', error);
      callback({ total: 0, critical: 0, error });
    }
  );
}
export async function acknowledgeAlert(alertId) {
  const alertRef = doc(db, 'alerts', alertId);
  await updateDoc(alertRef, { acknowledged: true });
}
export async function bulkAcknowledgeAlerts(alertIds) {
  const promises = alertIds.map((id) => acknowledgeAlert(id));
  await Promise.all(promises);
}
export async function getAlertsSince(since) {
  const q = query(
    collection(db, 'alerts'),
    where('timestamp', '>=', Timestamp.fromDate(since)),
    orderBy('timestamp', 'desc')
  );

  const snapshot = await getDocs(q);
  return snapshot.docs.map((docSnap) => ({
    id: docSnap.id,
    ...docSnap.data(),
    timestamp: docSnap.data().timestamp?.toDate?.()
      ? docSnap.data().timestamp.toDate()
      : new Date(docSnap.data().timestamp),
  }));
}
export async function getTrafficSnapshots(since) {
  const q = query(
    collection(db, 'traffic_snapshots'),
    where('timestamp', '>=', Timestamp.fromDate(since)),
    orderBy('timestamp', 'asc')
  );

  const snapshot = await getDocs(q);
  return snapshot.docs.map((docSnap) => ({
    id: docSnap.id,
    ...docSnap.data(),
    timestamp: docSnap.data().timestamp?.toDate?.()
      ? docSnap.data().timestamp.toDate()
      : new Date(docSnap.data().timestamp),
  }));
}
export async function getSystemConfig() {
  const { getDoc } = await import('firebase/firestore');
  const docRef = doc(db, 'system_config', 'main');
  const docSnap = await getDoc(docRef);

  if (docSnap.exists()) {
    return docSnap.data();
  }
  return {
    anomaly_threshold: 0.5,
    attack_threshold: 0.75,
    baseline_packets_per_sec: 100,
    contamination: 0.1,
    notification_enabled: true,
    severity_filter_min: 'low',
  };
}
export async function updateSystemConfig(updates) {
  const { setDoc } = await import('firebase/firestore');
  const docRef = doc(db, 'system_config', 'main');
  await setDoc(docRef, { ...updates, last_updated: Timestamp.now() }, { merge: true });
}
