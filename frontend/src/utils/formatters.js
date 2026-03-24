import { format, formatDistanceToNow, isValid, parseISO } from 'date-fns';
export function formatTimestamp(timestamp) {
  const date = toDate(timestamp);
  if (!date) return '—';
  return format(date, 'yyyy-MM-dd HH:mm:ss');
}
export function formatTime(timestamp) {
  const date = toDate(timestamp);
  if (!date) return '—';
  return format(date, 'HH:mm:ss');
}
export function formatRelativeTime(timestamp) {
  const date = toDate(timestamp);
  if (!date) return '—';
  return formatDistanceToNow(date, { addSuffix: true });
}
export function formatDateInput(date) {
  if (!date || !isValid(date)) return '';
  return format(date, 'yyyy-MM-dd');
}
export function toDate(timestamp) {
  if (!timestamp) return null;
  if (timestamp instanceof Date) {
    return isValid(timestamp) ? timestamp : null;
  }
  if (typeof timestamp.toDate === 'function') {
    return timestamp.toDate();
  }
  if (typeof timestamp === 'number') {
    const date = new Date(timestamp);
    return isValid(date) ? date : null;
  }

  // ISO string
  if (typeof timestamp === 'string') {
    const date = parseISO(timestamp);
    return isValid(date) ? date : null;
  }

  return null;
}
export function formatNumber(num) {
  if (num === null || num === undefined) return '—';
  return Number(num).toLocaleString('en-US');
}
export function formatCompact(num) {
  if (num === null || num === undefined) return '—';
  if (num >= 1e9) return (num / 1e9).toFixed(1) + 'B';
  if (num >= 1e6) return (num / 1e6).toFixed(1) + 'M';
  if (num >= 1e3) return (num / 1e3).toFixed(1) + 'K';
  return num.toFixed(0);
}
export function formatBytes(bytes) {
  if (bytes === 0 || bytes === null || bytes === undefined) return '0 B';

  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = bytes / Math.pow(1024, i);

  return `${val.toFixed(val >= 100 ? 0 : 1)} ${sizes[i]}`;
}
export function formatPercentage(score) {
  if (score === null || score === undefined) return '—';
  return Math.round(score * 100) + '%';
}
export function formatPPS(pps) {
  return formatCompact(pps) + ' pps';
}
