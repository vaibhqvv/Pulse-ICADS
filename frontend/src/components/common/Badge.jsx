import React from 'react';
import clsx from 'clsx';

/* ---- Severity: dot color + text color ---- */
const SEVERITY_DOT = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-600',
  low: 'bg-gray-400',
};

const SEVERITY_TEXT = {
  critical: 'text-red-700',
  high: 'text-orange-700',
  medium: 'text-yellow-700',
  low: 'text-gray-500',
};

/* ---- Classification: uses a subtle left-bar accent ---- */
const CLASS_BAR = {
  normal: 'bg-green-500',
  suspicious: 'bg-amber-500',
  attack: 'bg-red-500',
};

const CLASS_TEXT = {
  normal: 'text-green-700',
  suspicious: 'text-amber-700',
  attack: 'text-red-700',
};

const CLASS_BG = {
  normal: 'bg-green-50',
  suspicious: 'bg-amber-50',
  attack: 'bg-red-50',
};

function capitalize(str) {
  if (!str) return 'Unknown';
  return str.charAt(0).toUpperCase() + str.slice(1);
}
export function SeverityBadge({ severity, className }) {
  const key = severity?.toLowerCase() || 'low';
  return (
    <span className={clsx('inline-flex items-center gap-1.5', className)}>
      <span className={clsx('w-1.5 h-1.5 rounded-full flex-shrink-0', SEVERITY_DOT[key] || 'bg-gray-400')} />
      <span className={clsx('text-xs font-medium', SEVERITY_TEXT[key] || 'text-gray-500')}>
        {capitalize(severity)}
      </span>
    </span>
  );
}
export function ClassificationBadge({ classification, className }) {
  const key = classification?.toLowerCase() || 'normal';
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-0 rounded overflow-hidden',
        CLASS_BG[key] || 'bg-gray-50',
        className
      )}
    >
      <span className={clsx('w-[3px] self-stretch flex-shrink-0', CLASS_BAR[key] || 'bg-gray-400')} />
      <span className={clsx('text-[10px] font-medium tracking-wide uppercase px-2 py-[3px]', CLASS_TEXT[key] || 'text-gray-500')}>
        {capitalize(classification)}
      </span>
    </span>
  );
}
export default function Badge({ type = 'severity', value, className }) {
  if (type === 'classification') {
    return <ClassificationBadge classification={value} className={className} />;
  }
  return <SeverityBadge severity={value} className={className} />;
}
