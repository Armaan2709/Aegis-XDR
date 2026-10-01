import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ShieldAlert, Search, RefreshCw, X } from 'lucide-react';
import { alertsApi } from '../api';
import { Alert, AlertStatus } from '../types';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const Alerts: React.FC = () => {
  const queryClient = useQueryClient();
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [page, setPage] = useState(1);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  const { data: alertsResponse, isLoading, refetch } = useQuery({
    queryKey: ['alertsList', query, severityFilter, statusFilter, page],
    queryFn: () =>
      alertsApi.listAlerts({
        query: query || undefined,
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        page,
        page_size: 15,
      }),
  });

  const updateStatusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: AlertStatus }) => alertsApi.updateAlertStatus(id, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alertsList'] });
      queryClient.invalidateQueries({ queryKey: ['overviewMetrics'] });
      if (selectedAlert) {
        setSelectedAlert((prev) => (prev ? { ...prev, status: prev.status } : null));
      }
    },
  });

  if (isLoading) return <LoadingSpinner label="Loading Security Alerts..." />;

  const alerts = alertsResponse?.data || [];
  const meta = alertsResponse?.meta;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            <span>Alert Operations & SIEM Ingestion</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time security telemetry ingestion, severity classification, and analyst triage lifecycle.
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh Stream
        </button>
      </div>

      {/* Filter Toolbar */}
      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex-1 min-w-[200px] relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by title, host, IP, user, or hash..."
              className="w-full pl-9 pr-4 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-slate-500 font-mono"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none"
          >
            <option value="">All Lifecycle Statuses</option>
            <option value="NEW">NEW</option>
            <option value="IN_PROGRESS">IN_PROGRESS</option>
            <option value="TRIAGED">TRIAGED</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
          </select>
        </div>
      </Card>

      {/* Alerts Table */}
      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead className="bg-surfaceLight border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px] tracking-wider">
              <tr>
                <th className="p-3.5">Severity</th>
                <th className="p-3.5">Alert Details</th>
                <th className="p-3.5">Source</th>
                <th className="p-3.5">Host / Target</th>
                <th className="p-3.5">Risk Score</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5">Timestamp</th>
                <th className="p-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {alerts.length > 0 ? (
                alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3.5 whitespace-nowrap">
                      <Badge variant={alert.severity.toLowerCase() as any}>{alert.severity}</Badge>
                    </td>
                    <td className="p-3.5 font-sans">
                      <div className="font-semibold text-slate-100 text-xs">{alert.title}</div>
                      {alert.command_line && (
                        <code className="text-[11px] text-amber-300 font-mono block mt-0.5 truncate max-w-xs">
                          {alert.command_line}
                        </code>
                      )}
                    </td>
                    <td className="p-3.5 whitespace-nowrap text-slate-400">{alert.source}</td>
                    <td className="p-3.5 whitespace-nowrap text-slate-300">
                      {alert.host || alert.ip || alert.user || 'N/A'}
                    </td>
                    <td className="p-3.5 whitespace-nowrap font-bold text-amber-400">{alert.risk_score}</td>
                    <td className="p-3.5 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                        {alert.status}
                      </span>
                    </td>
                    <td className="p-3.5 whitespace-nowrap text-slate-500 text-[11px]">
                      {new Date(alert.created_at).toLocaleString()}
                    </td>
                    <td className="p-3.5 whitespace-nowrap text-right">
                      <button
                        onClick={() => setSelectedAlert(alert)}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-slate-500 font-mono">
                    No matching security alerts found in datastore.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        {meta && meta.total_pages > 1 && (
          <div className="p-4 border-t border-slate-800 flex items-center justify-between font-mono text-xs text-slate-400">
            <span>
              Page {meta.page} of {meta.total_pages} ({meta.total_items} items)
            </span>
            <div className="flex gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="px-3 py-1 bg-slate-800 rounded disabled:opacity-50"
              >
                Previous
              </button>
              <button
                disabled={page >= meta.total_pages}
                onClick={() => setPage((p) => p + 1)}
                className="px-3 py-1 bg-slate-800 rounded disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </Card>

      {/* Alert Inspector Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-surface border border-slate-700 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl overflow-y-auto max-h-[90vh]">
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <Badge variant={selectedAlert.severity.toLowerCase() as any}>{selectedAlert.severity}</Badge>
                  <span className="text-xs font-mono text-slate-400">ID: {selectedAlert.id}</span>
                </div>
                <h3 className="text-base font-bold text-slate-100 mt-1">{selectedAlert.title}</h3>
              </div>
              <button onClick={() => setSelectedAlert(null)} className="p-1 text-slate-400 hover:text-slate-200">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 text-xs font-mono">
              <div>
                <span className="text-slate-500 block">Source</span>
                <span className="text-slate-200 font-semibold">{selectedAlert.source}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Risk Score</span>
                <span className="text-amber-400 font-semibold">{selectedAlert.risk_score} / 100</span>
              </div>
              <div>
                <span className="text-slate-500 block">Host / IP</span>
                <span className="text-slate-200 font-semibold">{selectedAlert.host || selectedAlert.ip || 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">User Context</span>
                <span className="text-slate-200 font-semibold">{selectedAlert.user || 'N/A'}</span>
              </div>
            </div>

            {selectedAlert.command_line && (
              <div>
                <span className="text-xs font-mono text-slate-400 block mb-1">Executed Command Line</span>
                <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-amber-300 overflow-x-auto">
                  {selectedAlert.command_line}
                </pre>
              </div>
            )}

            {/* Triage Status Transition Action Buttons */}
            <div className="pt-4 border-t border-slate-800">
              <span className="text-xs font-mono text-slate-400 block mb-2">Transition Triage Lifecycle Status:</span>
              <div className="flex flex-wrap gap-2">
                {(['NEW', 'IN_PROGRESS', 'TRIAGED', 'RESOLVED', 'FALSE_POSITIVE'] as AlertStatus[]).map((st) => (
                  <button
                    key={st}
                    onClick={() => updateStatusMutation.mutate({ id: selectedAlert.id, status: st })}
                    className={`px-3 py-1.5 text-xs font-mono rounded border transition ${
                      selectedAlert.status === st
                        ? 'bg-emerald-950 text-emerald-400 border-emerald-700 font-bold'
                        : 'bg-slate-900 text-slate-300 border-slate-700 hover:bg-slate-800'
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
