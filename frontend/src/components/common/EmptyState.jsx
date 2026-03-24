import React from 'react';
import { Inbox } from 'lucide-react';

export default function EmptyState({
  icon: Icon = Inbox,
  title = 'No data available',
  description = 'Data will appear here once the system starts receiving traffic.',
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4">
      <Icon className="w-10 h-10 text-text-secondary/40 mb-4" />
      <h3 className="text-base font-medium text-text-secondary mb-1">{title}</h3>
      <p className="text-sm text-text-secondary/70 text-center max-w-sm">{description}</p>
    </div>
  );
}
