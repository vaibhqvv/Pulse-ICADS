import React from 'react';
import {
  ComposedChart,
  Area,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import { formatTime, formatCompact } from '../../utils/formatters';

export default function TrafficTimeline({ data = [], baseline = 100 }) {
  if (data.length === 0) {
    return (
      <div className="card p-4 h-[300px] flex items-center justify-center">
        <p className="text-text-secondary text-sm">No traffic data available</p>
      </div>
    );
  }

  const formattedData = data.map((d) => ({
    ...d,
    time: typeof d.timestamp === 'object' ? formatTime(d.timestamp) : d.time || '',
  }));

  return (
    <div className="card p-4">
      <h3 className="text-sm font-medium text-text-secondary mb-3">
        Traffic Timeline
      </h3>
      <ResponsiveContainer width="100%" height={280}>
        <ComposedChart data={formattedData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#E5E2DD" />
          <XAxis
            dataKey="time"
            tick={{ fill: '#7A756E', fontSize: 10 }}
            tickLine={{ stroke: '#E5E2DD' }}
            interval="preserveStartEnd"
          />
          <YAxis
            yAxisId="left"
            tick={{ fill: '#7A756E', fontSize: 10 }}
            tickFormatter={(v) => formatCompact(v)}
            label={{ value: 'Packets/s', angle: -90, position: 'insideLeft', fill: '#7A756E', fontSize: 11 }}
          />
          <YAxis
            yAxisId="right"
            orientation="right"
            tick={{ fill: '#7A756E', fontSize: 10 }}
            tickFormatter={(v) => formatCompact(v)}
            label={{ value: 'Bytes/s', angle: 90, position: 'insideRight', fill: '#7A756E', fontSize: 11 }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#FFFFFF',
              border: '1px solid #E5E2DD',
              borderRadius: '6px',
              color: '#2D2A26',
              fontSize: '12px',
            }}
          />
          <ReferenceLine
            yAxisId="left"
            y={baseline * 3}
            stroke="#B44B4B"
            strokeDasharray="5 5"
            label={{ value: 'Spike', fill: '#B44B4B', fontSize: 10 }}
          />
          <Area
            yAxisId="left"
            type="monotone"
            dataKey="packets_per_sec"
            fill="#4A6741"
            fillOpacity={0.1}
            stroke="#4A6741"
            strokeWidth={2}
            name="Packets/sec"
          />
          <Line
            yAxisId="right"
            type="monotone"
            dataKey="bytes_per_sec"
            stroke="#8B7355"
            strokeWidth={1.5}
            dot={false}
            name="Bytes/sec"
          />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}
