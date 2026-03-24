import React from 'react';
import { Search, X } from 'lucide-react';

export default function AlertFilters({ filters, onFilterChange, onClear }) {
  const handleChange = (key, value) => {
    onFilterChange({ ...filters, [key]: value });
  };

  const hasActiveFilters =
    filters.searchTerm ||
    (filters.severity && filters.severity !== 'all') ||
    (filters.classification && filters.classification !== 'all') ||
    (filters.source && filters.source !== 'all') ||
    filters.startDate ||
    filters.endDate;

  return (
    <div className="card p-4 mb-4">
      <div className="flex flex-wrap gap-3 items-end">
        {/* Search input */}
        <div className="flex-1 min-w-[200px]">
          <label className="block text-xs text-text-secondary mb-1">Search</label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary" />
            <input
              type="text"
              placeholder="Search by IP, alert type, category..."
              value={filters.searchTerm || ''}
              onChange={(e) => handleChange('searchTerm', e.target.value)}
              className="input-dark w-full pl-9"
            />
          </div>
        </div>

        {/* Severity dropdown */}
        <div className="w-36">
          <label className="block text-xs text-text-secondary mb-1">Severity</label>
          <select
            value={filters.severity || 'all'}
            onChange={(e) => handleChange('severity', e.target.value)}
            className="select-dark w-full"
          >
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        {/* Classification dropdown */}
        <div className="w-36">
          <label className="block text-xs text-text-secondary mb-1">Classification</label>
          <select
            value={filters.classification || 'all'}
            onChange={(e) => handleChange('classification', e.target.value)}
            className="select-dark w-full"
          >
            <option value="all">All</option>
            <option value="normal">Normal</option>
            <option value="suspicious">Suspicious</option>
            <option value="attack">Attack</option>
          </select>
        </div>

        {/* Source dropdown */}
        <div className="w-36">
          <label className="block text-xs text-text-secondary mb-1">Source</label>
          <select
            value={filters.source || 'all'}
            onChange={(e) => handleChange('source', e.target.value)}
            className="select-dark w-full"
          >
            <option value="all">All</option>
            <option value="suricata">Suricata</option>
            <option value="simulation">Simulation</option>
            <option value="anomaly">Anomaly</option>
          </select>
        </div>

        {/* Date range: From */}
        <div className="w-40">
          <label className="block text-xs text-text-secondary mb-1">From</label>
          <input
            type="date"
            value={filters.startDate || ''}
            onChange={(e) =>
              handleChange('startDate', e.target.value ? new Date(e.target.value) : null)
            }
            className="input-dark w-full"
          />
        </div>

        {/* Date range: To */}
        <div className="w-40">
          <label className="block text-xs text-text-secondary mb-1">To</label>
          <input
            type="date"
            value={filters.endDate || ''}
            onChange={(e) =>
              handleChange('endDate', e.target.value ? new Date(e.target.value) : null)
            }
            className="input-dark w-full"
          />
        </div>

        {/* Clear filters button */}
        {hasActiveFilters && (
          <button
            onClick={onClear}
            className="btn-secondary flex items-center gap-1.5 text-sm"
          >
            <X className="w-4 h-4" />
            Clear
          </button>
        )}
      </div>
    </div>
  );
}
