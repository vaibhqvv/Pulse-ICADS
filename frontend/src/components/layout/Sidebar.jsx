import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  AlertTriangle,
  BarChart3,
  Settings,
  LogOut,
  X,
} from 'lucide-react';
import clsx from 'clsx';
import { useAuthContext } from '../../context/AuthContext';
import { useTrafficMetrics } from '../../hooks/useTrafficMetrics';
import { STATUS_COLORS, STATUS_LABELS } from '../../utils/classifyAlert';

const NAV_ITEMS = [
  { path: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/alerts', icon: AlertTriangle, label: 'Alerts' },
  { path: '/analytics', icon: BarChart3, label: 'Analytics' },
  { path: '/settings', icon: Settings, label: 'Settings' },
];

export default function Sidebar({ isOpen, onClose }) {
  const { user, logout } = useAuthContext();
  const { liveMetrics } = useTrafficMetrics();
  const navigate = useNavigate();

  const systemStatus = liveMetrics?.system_status || 'offline';

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <>
      {/* Mobile overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/30 z-40 lg:hidden"
          onClick={onClose}
        />
      )}

      {/* Sidebar */}
      <aside
        className={clsx(
          'fixed top-0 left-0 h-full z-50',
          'flex flex-col transition-transform duration-200',
          'w-[220px] lg:translate-x-0',
          'border-r border-gray-200',
          isOpen ? 'translate-x-0' : '-translate-x-full'
        )}
        style={{ backgroundColor: '#F9F7F3', color: '#1A1714' }}
      >
        {/* Logo */}
        <div className="flex items-center justify-between px-5 py-5">
          <div className="flex items-center gap-2.5">
            <Shield className="w-5 h-5 text-accent-blue" />
            <div>
              <h1 className="font-heading text-lg text-text-primary">Pulse</h1>
              <p className="text-[10px] text-text-secondary font-mono">Threat Monitor</p>
            </div>
          </div>
          <button onClick={onClose} className="lg:hidden text-text-secondary hover:text-text-primary">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Divider */}
        <div className="mx-4 h-px bg-gray-200" />

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
          {NAV_ITEMS.map(({ path, icon: Icon, label }) => (
            <NavLink
              key={path}
              to={path}
              onClick={onClose}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors duration-150',
                  isActive
                    ? 'bg-green-50 text-accent-blue font-medium'
                    : 'text-text-secondary hover:text-text-primary hover:bg-gray-50'
                )
              }
            >
              <Icon className="w-[18px] h-[18px] flex-shrink-0" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Bottom */}
        <div className="px-4 py-3.5 border-t border-gray-200">
          {/* System status */}
          <div className="flex items-center gap-2 mb-3">
            <div
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: STATUS_COLORS[systemStatus] || STATUS_COLORS.offline }}
            />
            <span className="text-xs text-text-secondary">
              {STATUS_LABELS[systemStatus] || 'Offline'}
            </span>
          </div>

          {/* User + logout */}
          <div className="flex items-center justify-between">
            <span className="text-xs text-text-secondary truncate max-w-[130px]">
              {user?.email || 'Not logged in'}
            </span>
            <button
              onClick={handleLogout}
              className="p-1.5 rounded text-text-secondary hover:text-red-600 hover:bg-red-50 transition-colors"
              title="Logout"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}
