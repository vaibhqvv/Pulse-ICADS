// Classification colors (for charts, badges, and indicators)
export const CLASSIFICATION_COLORS = {
  normal: '#5B8A52',
  suspicious: '#B8963E',
  attack: '#B44B4B',
};

export const CLASSIFICATION_BG = {
  normal: 'bg-green-50',
  suspicious: 'bg-amber-50',
  attack: 'bg-red-50',
};

export const CLASSIFICATION_TEXT = {
  normal: 'text-green-700',
  suspicious: 'text-amber-700',
  attack: 'text-red-700',
};

export const CLASSIFICATION_BORDER = {
  normal: 'border-green-200',
  suspicious: 'border-amber-200',
  attack: 'border-red-200',
};

export const CLASSIFICATION_LABELS = {
  normal: 'Normal',
  suspicious: 'Suspicious',
  attack: 'Attack',
};

// Severity colors
export const SEVERITY_COLORS = {
  critical: '#B44B4B',
  high: '#C67A3C',
  medium: '#B8963E',
  low: '#8E8E8E',
};

export const SEVERITY_BG = {
  critical: 'bg-red-50',
  high: 'bg-orange-50',
  medium: 'bg-yellow-50',
  low: 'bg-gray-50',
};

export const SEVERITY_TEXT = {
  critical: 'text-red-700',
  high: 'text-orange-700',
  medium: 'text-yellow-700',
  low: 'text-gray-500',
};

export const SEVERITY_BORDER = {
  critical: 'border-red-200',
  high: 'border-orange-200',
  medium: 'border-yellow-200',
  low: 'border-gray-200',
};

export const SEVERITY_LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

// System status colors
export const STATUS_COLORS = {
  normal: '#5B8A52',
  warning: '#B8963E',
  critical: '#B44B4B',
  training: '#4A6741',
  offline: '#8E8E8E',
};

export const STATUS_LABELS = {
  normal: 'Normal',
  warning: 'Warning',
  critical: 'Critical',
  training: 'Training',
  offline: 'Offline',
};
export function getClassificationBadgeClass(classification) {
  const key = classification?.toLowerCase() || 'normal';
  return `${CLASSIFICATION_BG[key] || ''} ${CLASSIFICATION_TEXT[key] || ''} ${CLASSIFICATION_BORDER[key] || ''}`;
}
export function getSeverityBadgeClass(severity) {
  const key = severity?.toLowerCase() || 'low';
  return `${SEVERITY_BG[key] || ''} ${SEVERITY_TEXT[key] || ''} ${SEVERITY_BORDER[key] || ''}`;
}
