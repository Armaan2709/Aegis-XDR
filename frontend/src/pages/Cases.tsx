import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Briefcase, Search, RefreshCw, AlertTriangle } from 'lucide-react';
import { casesApi } from '../api';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const Cases: React.FC = () => {
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(1);

  const { data: casesResponse, isLoading, refetch } = useQuery({
    queryKey: ['casesList', query, statusFilter, page],
    queryFn: () =>
      casesApi.listCases({
        query: query || undefined,
        status: statusFilter || undefined,
        page,
        page_size: 15,
      }),
  });

  if (isLoading) return <LoadingSpinner label="Loading Case Workspaces..." />;

  const cases = casesResponse?.data || [];
  const meta = casesResponse?.meta;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Briefcase className="w-5 h-5 text-purple-400" />
            <span>Case Management Workspaces</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Enterprise case investigation workspaces, analyst assignments, and SLA breach tracking.
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
              placeholder="Search case number, title..."
              className="w-full pl-9 pr-4 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none font-mono"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono"
          >
            <option value="">All Case Statuses</option>
            <option value="OPEN">OPEN</option>
            <option value="IN_PROGRESS">IN_PROGRESS</option>
            <option value="PENDING_APPROVAL">PENDING_APPROVAL</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="CLOSED">CLOSED</option>
          </select>
        </div>
      </Card>

      {/* Cases Table */}
      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead className="bg-surfaceLight border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px] tracking-wider">
              <tr>
                <th className="p-3.5">Case Number</th>
                <th className="p-3.5">Title</th>
                <th className="p-3.5">Severity</th>
                <th className="p-3.5">Priority</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5">SLA Target State</th>
                <th className="p-3.5 text-right">Opened At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {cases.length > 0 ? (
                cases.map((c) => (
                  <tr key={c.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3.5 whitespace-nowrap">
                      <span className="px-2 py-1 rounded bg-slate-900 text-purple-300 font-bold border border-slate-700">
                        {c.case_number}
                      </span>
                    </td>
                    <td className="p-3.5 font-sans">
                      <div className="font-semibold text-slate-100">{c.title}</div>
                    </td>
                    <td className="p-3.5 whitespace-nowrap">
                      <Badge variant={c.severity.toLowerCase() as any}>{c.severity}</Badge>
                    </td>
                    <td className="p-3.5 whitespace-nowrap text-slate-300 font-bold">{c.priority}</td>
                    <td className="p-3.5 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                        {c.status}
                      </span>
                    </td>
                    <td className="p-3.5 whitespace-nowrap">
                      {c.sla_breached ? (
                        <span className="inline-flex items-center gap-1 text-[10px] text-red-400 font-bold bg-red-950/60 px-2 py-0.5 rounded border border-red-800">
                          <AlertTriangle className="w-3 h-3" /> SLA BREACHED
                        </span>
                      ) : (
                        <span className="text-[10px] text-emerald-400 font-bold">WITHIN SLA</span>
                      )}
                    </td>
                    <td className="p-3.5 whitespace-nowrap text-right text-slate-500 text-[11px]">
                      {new Date(c.opened_at || c.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500 font-mono">
                    No active case workspaces found.
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
    </div>
  );
};
