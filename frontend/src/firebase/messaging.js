import { getToken, onMessage } from 'firebase/messaging';
import { getMessagingInstance } from './config';

const VAPID_KEY = import.meta.env.VITE_FIREBASE_VAPID_KEY;
export async function requestNotificationPermission() {
  const messaging = getMessagingInstance();
  if (!messaging) {
    console.warn('FCM not supported in this browser');
    return null;
  }

  try {
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') {
      console.warn('Notification permission denied');
      return null;
    }
    const token = await getToken(messaging, { vapidKey: VAPID_KEY });
    console.log('FCM token obtained:', token?.substring(0, 20) + '...');
    return token;
  } catch (error) {
    console.error('Failed to get FCM token:', error);
    return null;
  }
}
export function onForegroundMessage(callback) {
  const messaging = getMessagingInstance();
  if (!messaging) {
    return () => {};  // No-op cleanup if messaging not supported
  }

  return onMessage(messaging, (payload) => {
    console.log('Foreground FCM message:', payload);
    callback(payload);
  });
}
export function showAlertNotification(alert) {
  if (!('Notification' in window) || Notification.permission !== 'granted') {
    return;
  }

  const title = alert.alert_type || 'Pulse Alert';
  const body = `${alert.severity?.toUpperCase()} | ${alert.src_ip} → ${alert.dest_ip}`;

  new Notification(title, {
    body,
    icon: '/favicon.ico',
    tag: alert.id || 'icads-alert',  // Prevent duplicate notifications
    requireInteraction: alert.severity === 'critical',
  });
}
