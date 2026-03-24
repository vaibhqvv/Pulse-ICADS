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
import EmptyState from '../common/EmptyState';
import { Activity } from 'lucide-react';

const SPIKE_THRESHOLD_MULTIPLIER = 3;
const DEFAULT_BASELINE = 100;

export default function TrafficChart({ data = [], baseline = DEFAULT_BASELINE }) {
  const spikeThreshold = baseline * SPIKE_THRESHOLD_MULTIPLIER;

  if (data.length === 0) {
    return (
      <div className="card p-4">
        <h3 className="text-sm font-medium text-text-secondary mb-3">
          Live Traffic
        </h3>
        <EmptyState
          icon={Activity}
          title="Waiting for traffic data"
          description="Chart will populate once the Python backend starts sending metrics."
        />
      </div>
    );
  }

  return (
    <div className="card p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-text-secondary">
          Live Traffic (Packets/sec)
        </h3>
        <span className="text-xs text-text-secondary">
          Last {data.length} readings
        </span>
      </div>

      <ResponsiveContainer width="100%" height={250}>
        <LineChart data={data} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#E5E2DD" />
          <XAxis
            dataKey="time"
            tick={{ fill: '#7A756E', fontSize: 11 }}
            tickLine={{ stroke: '#E5E2DD' }}
            axisLine={{ stroke: '#E5E2DD' }}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fill: '#7A756E', fontSize: 11 }}
            tickLine={{ stroke: '#E5E2DD' }}
            axisLine={{ stroke: '#E5E2DD' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#FFFFFF',
              border: '1px solid #E5E2DD',
              borderRadius: '6px',
              color: '#2D2A26',
              fontSize: '13px',
            }}
            labelStyle={{ color: '#7A756E' }}
          />

          <ReferenceLine
            y={spikeThreshold}
            stroke="#B44B4B"
            strokeDasharray="5 5"
            label={{
              value: `Spike (${spikeThreshold})`,
              fill: '#B44B4B',
              fontSize: 11,
              position: 'right',
            }}
          />

          <Line
            type="monotone"
            dataKey="packets_per_sec"
            stroke="#4A6741"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4, fill: '#4A6741' }}
            name="Packets/sec"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
