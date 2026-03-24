import React from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  ResponsiveContainer,
} from 'recharts';
import { formatTime } from '../../utils/formatters';

export default function AnomalyChart({
  data = [],
  anomalyThreshold = 0.5,
  attackThreshold = 0.75,
}) {
  if (data.length === 0) {
    return (
      <div className="card p-4 h-[300px] flex items-center justify-center">
        <p className="text-text-secondary text-sm">No anomaly data available</p>
      </div>
    );
  }

  const formattedData = data.map((d) => ({
    ...d,
    time: typeof d.timestamp === 'object' ? formatTime(d.timestamp) : d.time || '',
  }));
  const renderDot = (props) => {
    const { cx, cy, payload } = props;
    if (!cx || !cy) return null;
    const color = payload.anomaly_score >= attackThreshold ? '#B44B4B' : '#4A6741';
    return <circle cx={cx} cy={cy} r={3} fill={color} stroke="none" />;
  };

  return (
    <div className="card p-4">
      <h3 className="text-sm font-medium text-text-secondary mb-3">
        Anomaly Score Trend
      </h3>
      <ResponsiveContainer width="100%" height={280}>
        <LineChart data={formattedData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#E5E2DD" />
          <XAxis
            dataKey="time"
            tick={{ fill: '#7A756E', fontSize: 10 }}
            tickLine={{ stroke: '#E5E2DD' }}
            interval="preserveStartEnd"
          />
          <YAxis
            domain={[0, 1]}
            tick={{ fill: '#7A756E', fontSize: 10 }}
            tickLine={{ stroke: '#E5E2DD' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#FFFFFF',
              border: '1px solid #E5E2DD',
              borderRadius: '6px',
              color: '#2D2A26',
              fontSize: '12px',
            }}
            formatter={(value) => [value?.toFixed(4), 'Anomaly Score']}
          />

          <ReferenceLine
            y={anomalyThreshold}
            stroke="#B8963E"
            strokeDasharray="5 5"
            label={{ value: `Suspicious (${anomalyThreshold})`, fill: '#B8963E', fontSize: 10, position: 'right' }}
          />
          <ReferenceLine
            y={attackThreshold}
            stroke="#B44B4B"
            strokeDasharray="5 5"
            label={{ value: `Attack (${attackThreshold})`, fill: '#B44B4B', fontSize: 10, position: 'right' }}
          />

          <Line
            type="monotone"
            dataKey="anomaly_score"
            stroke="#4A6741"
            strokeWidth={2}
            dot={renderDot}
            activeDot={{ r: 5 }}
            name="Anomaly Score"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
