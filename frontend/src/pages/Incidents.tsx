import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { AlertTriangle, Search, RefreshCw, FileSearch, X } from 'lucide-react';
import { incidentsApi } from '../api';
import { Incident } from '../types';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const Incidents: React.FC = () => {
  const queryClient = useQueryClient();
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(1);

  const [closingIncident, setClosingIncident] = useState<Incident | null>(null);
  const [closureNotes, setClosureNotes] = useState('');

  const { data: incidentsResponse, isLoading, refetch } = useQuery({
    queryKey: ['incidentsList', query, severityFilter, statusFilter, page],
    queryFn: () =>
      incidentsApi.listIncidents({
        query: query || undefined,
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        page,
        page_size: 15,
      }),
  });

  const closeMutation = useMutation({
    mutationFn: ({ id, notes }: { id: string; notes: string }) => incidentsApi.closeIncident(id, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidentsList'] });
      queryClient.invalidateQueries({ queryKey: ['overviewMetrics'] });
      setClosingIncident(null);
      setClosureNotes('');
    },
  });

  if (isLoading) return <LoadingSpinner label="Loading Incidents..." />;

  const incidents = incidentsResponse?.data || [];
  const meta = incidentsResponse?.meta;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <span>Incident Command Center</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Correlated threat incidents, severity prioritization, and autonomous AI pipeline trigger point.
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
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
              placeholder="Search code, title, category..."
              className="w-full pl-9 pr-4 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-slate-500 font-mono"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono"
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
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono"
          >
            <option value="">All Statuses</option>
            <option value="OPEN">OPEN</option>
            <option value="TRIAGED">TRIAGED</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="CONTAINED">CONTAINED</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="CLOSED">CLOSED</option>
          </select>
        </div>
      </Card>

      {/* Incidents Table */}
      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead className="bg-surfaceLight border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px] tracking-wider">
              <tr>
                <th className="p-3.5">Incident Code</th>
                <th className="p-3.5">Severity / Priority</th>
                <th className="p-3.5">Title & Category</th>
                <th className="p-3.5">Risk Score</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5">Created At</th>
                <th className="p-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {incidents.length > 0 ? (
                incidents.map((incident) => (
                  <tr key={incident.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3.5 whitespace-nowrap">
                      <span className="px-2 py-1 rounded bg-slate-900 text-slate-200 font-bold border border-slate-700">
                        {incident.incident_code}
                      </span>
                    </td>
                    <td className="p-3.5 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <Badge variant={incident.severity.toLowerCase() as any}>{incident.severity}</Badge>
                        <span className="text-[10px] text-slate-400">{incident.priority}</span>
                      </div>
                    </td>
                    <td className="p-3.5 font-sans">
                      <div className="font-semibold text-slate-100">{incident.title}</div>
                      <span className="text-[10px] font-mono text-purple-400">{incident.category}</span>
                    </td>
                    <td className="p-3.5 whitespace-nowrap font-bold text-amber-400">{incident.risk_score}</td>
                    <td className="p-3.5 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                        {incident.status}
                      </span>
                    </td>
                    <td className="p-3.5 whitespace-nowrap text-slate-500 text-[11px]">
                      {new Date(incident.created_at).toLocaleString()}
                    </td>
                    <td className="p-3.5 whitespace-nowrap text-right space-x-2">
                      <Link
                        to={`/investigations?incident_id=${incident.id}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 bg-emerald-950 text-emerald-400 border border-emerald-800 rounded hover:bg-emerald-900 transition"
                      >
                        <FileSearch className="w-3.5 h-3.5" />
                        Run AI Investigation
                      </Link>

                      {incident.status !== 'CLOSED' && (
                        <button
                          onClick={() => setClosingIncident(incident)}
                          className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition"
                        >
                          Close
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500 font-mono">
                    No security incidents matching current query.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

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

      {/* Closure Modal */}
      {closingIncident && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-surface border border-slate-700 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100">Close Incident {closingIncident.incident_code}</h3>
              <button onClick={() => setClosingIncident(null)} className="text-slate-400 hover:text-slate-200">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div>
              <label className="text-xs font-mono text-slate-400 block mb-1">Mandatory Closure Summary Notes:</label>
              <textarea
                value={closureNotes}
                onChange={(e) => setClosureNotes(e.target.value)}
                rows={4}
                placeholder="Detail root cause, containment steps, and post-incident remediation..."
                className="w-full p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-slate-600"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button onClick={() => setClosingIncident(null)} className="px-4 py-1.5 bg-slate-800 text-slate-300 rounded text-xs">
                Cancel
              </button>
              <button
                disabled={!closureNotes.trim()}
                onClick={() => closeMutation.mutate({ id: closingIncident.id, notes: closureNotes })}
                className="px-4 py-1.5 bg-red-950 text-red-300 border border-red-800 hover:bg-red-900 rounded text-xs disabled:opacity-50 font-mono"
              >
                Confirm Closure
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
