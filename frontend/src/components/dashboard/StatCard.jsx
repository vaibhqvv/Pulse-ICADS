import React from 'react';
import clsx from 'clsx';

export default function StatCard({ title, value, icon: Icon, trend, color = '#4A6741', subtitle }) {
  return (
    <div className="card p-4 sm:p-5">
      <div className="flex items-start justify-between mb-3">
        <Icon className="w-5 h-5" style={{ color }} />

        {trend !== undefined && trend !== null && (
          <span
            className={clsx(
              'font-data text-xs px-1.5 py-0.5 rounded',
              trend >= 0
                ? 'text-green-700 bg-green-50'
                : 'text-red-700 bg-red-50'
            )}
          >
            {trend >= 0 ? '+' : ''}{trend}%
          </span>
        )}
      </div>

      <p className="font-heading text-2xl sm:text-3xl text-text-primary mb-0.5">
        {value ?? '—'}
      </p>

      <p className="text-sm text-text-secondary">{title}</p>

      {subtitle && (
        <p className="text-xs mt-1.5" style={{ color }}>
          {subtitle}
        </p>
      )}
    </div>
  );
}
