import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Fingerprint, Search, RefreshCw } from 'lucide-react';
import { threatIntelApi } from '../api';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const ThreatIntel: React.FC = () => {
  const [query, setQuery] = useState('');
  const [iocType, setIocType] = useState('');
  const [reputation, setReputation] = useState('');
  const [page, setPage] = useState(1);

  const { data: iocResponse, isLoading, refetch } = useQuery({
    queryKey: ['iocList', query, iocType, reputation, page],
    queryFn: () =>
      threatIntelApi.listIOCs({
        query: query || undefined,
        ioc_type: iocType || undefined,
        reputation_level: reputation || undefined,
        page,
        page_size: 15,
      }),
  });


  if (isLoading) return <LoadingSpinner label="Querying Threat Intelligence Feeds..." />;

  const iocs = iocResponse?.data || [];
  const meta = iocResponse?.meta;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Fingerprint className="w-5 h-5 text-purple-400" />
            <span>Threat Intelligence & IOC Management</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Aggregated threat feeds, indicator reputation scoring, and threat actor profiling.
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Sync Feeds
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
              placeholder="Search indicator, threat actor, category..."
              className="w-full pl-9 pr-4 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none font-mono"
            />
          </div>

          <select
            value={iocType}
            onChange={(e) => setIocType(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono"
          >
            <option value="">All Indicator Types</option>
            <option value="IP">IP Address</option>
            <option value="DOMAIN">Domain Name</option>
            <option value="URL">URL</option>
            <option value="FILE_HASH_SHA256">File Hash (SHA256)</option>
          </select>

          <select
            value={reputation}
            onChange={(e) => setReputation(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono"
          >
            <option value="">All Reputations</option>
            <option value="MALICIOUS">MALICIOUS</option>
            <option value="SUSPICIOUS">SUSPICIOUS</option>
            <option value="BENIGN">BENIGN</option>
            <option value="UNKNOWN">UNKNOWN</option>
          </select>
        </div>
      </Card>

      {/* IOC Table */}
      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead className="bg-surfaceLight border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px] tracking-wider">
              <tr>
                <th className="p-3.5">Indicator Value</th>
                <th className="p-3.5">Type</th>
                <th className="p-3.5">Reputation</th>
                <th className="p-3.5">Risk Score</th>
                <th className="p-3.5">Confidence</th>
                <th className="p-3.5">Threat Category</th>
                <th className="p-3.5 text-right">First / Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {iocs.length > 0 ? (
                iocs.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3.5 font-bold text-slate-100">{ioc.indicator_value}</td>
                    <td className="p-3.5 whitespace-nowrap text-purple-400">{ioc.ioc_type}</td>
                    <td className="p-3.5 whitespace-nowrap">
                      <Badge variant={ioc.reputation_level === 'MALICIOUS' ? 'critical' : ioc.reputation_level === 'SUSPICIOUS' ? 'warning' : 'neutral'}>
                        {ioc.reputation_level}
                      </Badge>
                    </td>
                    <td className="p-3.5 whitespace-nowrap font-bold text-amber-400">{ioc.risk_score}</td>
                    <td className="p-3.5 whitespace-nowrap text-slate-300">{ioc.confidence_score}%</td>
                    <td className="p-3.5 whitespace-nowrap text-slate-400">{ioc.threat_category || 'APT / Malware'}</td>
                    <td className="p-3.5 whitespace-nowrap text-right text-slate-500 text-[11px]">
                      {ioc.first_seen ? new Date(ioc.first_seen).toLocaleDateString() : 'N/A'}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500 font-mono">
                    No threat indicators found.
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
