import React, { useState, useEffect } from 'react';
import { Bell, Menu } from 'lucide-react';
import { useAuthContext } from '../../context/AuthContext';
import { useTodayAlertCounts } from '../../hooks/useAlerts';
import { format } from 'date-fns';

export default function Topbar({ title, onMenuClick }) {
  const { user } = useAuthContext();
  const { criticalToday } = useTodayAlertCounts();
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <header className="sticky top-0 z-30 border-b border-gray-200" style={{ backgroundColor: '#F9F7F3', color: '#1A1714' }}>
      <div className="flex items-center justify-between px-5 sm:px-6 h-[52px]">
        {/* Left */}
        <div className="flex items-center gap-3">
          <button
            onClick={onMenuClick}
            className="lg:hidden p-1.5 rounded text-text-secondary hover:text-text-primary hover:bg-gray-50"
          >
            <Menu className="w-4.5 h-4.5" />
          </button>
          <h1 className="font-heading text-lg text-text-primary">{title}</h1>
        </div>

        {/* Right */}
        <div className="flex items-center gap-3">
          <span className="hidden sm:block font-data text-xs text-text-secondary">
            {format(currentTime, 'HH:mm:ss')}
          </span>

          <div className="w-px h-4 bg-gray-200 hidden sm:block" />

          {/* Bell */}
          <button className="relative p-1.5 rounded text-text-secondary hover:text-text-primary hover:bg-gray-50 transition-colors">
            <Bell className="w-4 h-4" />
            {criticalToday > 0 && (
              <span className="absolute -top-0.5 -right-0.5 flex items-center justify-center w-4 h-4 bg-severity-critical text-white text-[9px] font-bold rounded-full">
                {criticalToday > 99 ? '99' : criticalToday}
              </span>
            )}
          </button>

          {/* User */}
          <span className="hidden md:block text-xs text-text-secondary truncate max-w-[160px]">
            {user?.email}
          </span>
        </div>
      </div>
    </header>
  );
}
