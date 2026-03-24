import React from 'react';
import { Loader2 } from 'lucide-react';

export default function LoadingSpinner({ fullScreen = false, message = 'Loading...' }) {
  if (fullScreen) {
    return (
      <div className="fixed inset-0 bg-bg-primary flex flex-col items-center justify-center z-50">
        <Loader2 className="w-8 h-8 text-accent-blue animate-spin mb-4" />
        <h2 className="font-heading text-xl text-text-primary mb-2">Pulse</h2>
        <p className="text-text-secondary text-sm">{message}</p>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center py-12">
      <div className="flex flex-col items-center gap-3">
        <Loader2 className="w-6 h-6 text-accent-blue animate-spin" />
        <p className="text-text-secondary text-sm">{message}</p>
      </div>
    </div>
  );
}
