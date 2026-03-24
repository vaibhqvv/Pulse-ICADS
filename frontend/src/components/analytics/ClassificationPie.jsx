import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { CLASSIFICATION_COLORS, CLASSIFICATION_LABELS } from '../../utils/classifyAlert';

export default function ClassificationPie({ alerts = [], title = 'Classification Breakdown' }) {
  const counts = { normal: 0, suspicious: 0, attack: 0 };
  alerts.forEach((a) => {
    const cls = a.classification?.toLowerCase();
    if (cls in counts) counts[cls]++;
  });

  const data = Object.entries(counts)
    .filter(([, count]) => count > 0)
    .map(([key, count]) => ({
      name: CLASSIFICATION_LABELS[key] || key,
      value: count,
      color: CLASSIFICATION_COLORS[key] || '#8E8E8E',
    }));

  const total = data.reduce((sum, d) => sum + d.value, 0);

  if (total === 0) {
    return (
      <div className="card p-4 h-[300px] flex items-center justify-center">
        <p className="text-text-secondary text-sm">No classification data</p>
      </div>
    );
  }

  return (
    <div className="card p-4">
      <h3 className="text-sm font-medium text-text-secondary mb-3">
        {title}
      </h3>
      <ResponsiveContainer width="100%" height={250}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={85}
            paddingAngle={3}
            dataKey="value"
            stroke="none"
          >
            {data.map((entry, index) => (
              <Cell key={index} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#FFFFFF',
              border: '1px solid #E5E2DD',
              borderRadius: '6px',
              color: '#2D2A26',
              fontSize: '13px',
            }}
            formatter={(value) => [
              `${value} (${((value / total) * 100).toFixed(1)}%)`,
              'Count',
            ]}
          />
          <Legend
            verticalAlign="bottom"
            iconType="circle"
            formatter={(value) => (
              <span className="text-text-secondary text-xs">{value}</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>

      <div className="text-center -mt-4">
        <p className="text-2xl font-heading text-text-primary">{total}</p>
        <p className="text-xs text-text-secondary">Total Alerts</p>
      </div>
    </div>
  );
}
