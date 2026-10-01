import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Code2, Search, RefreshCw, X } from 'lucide-react';
import { detectionsApi } from '../api';
import { DetectionRule } from '../types';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const Detections: React.FC = () => {
  const [query, setQuery] = useState('');
  const [ruleType, setRuleType] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(1);
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null);

  const { data: rulesResponse, isLoading, refetch } = useQuery({
    queryKey: ['rulesList', query, ruleType, statusFilter, page],
    queryFn: () =>
      detectionsApi.listRules({
        query: query || undefined,
        rule_type: ruleType || undefined,
        status: statusFilter || undefined,
        page,
        page_size: 15,
      }),
  });

  if (isLoading) return <LoadingSpinner label="Loading Detection Rules..." />;

  const rules = rulesResponse?.data || [];
  const meta = rulesResponse?.meta;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Code2 className="w-5 h-5 text-blue-400" />
            <span>Detection Rule Engine & Generator</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Sigma, YARA, Suricata detection lifecycle management, quality scoring, and AI rule generation.
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Reload Rules
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
              placeholder="Search rule code, name, category..."
              className="w-full pl-9 pr-4 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none font-mono"
            />
          </div>

          <select
            value={ruleType}
            onChange={(e) => setRuleType(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono"
          >
            <option value="">All Rule Formats</option>
            <option value="SIGMA">Sigma</option>
            <option value="YARA">YARA</option>
            <option value="SURICATA">Suricata</option>
            <option value="CUSTOM">Custom DSL</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono"
          >
            <option value="">All Rule Lifecycle Statuses</option>
            <option value="CANDIDATE">CANDIDATE (Candidate)</option>
            <option value="ACTIVE">ACTIVE (Production)</option>
            <option value="EXPERIMENTAL">EXPERIMENTAL</option>
            <option value="DEPRECATED">DEPRECATED</option>
          </select>
        </div>
      </Card>

      {/* Rules Table */}
      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead className="bg-surfaceLight border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px] tracking-wider">
              <tr>
                <th className="p-3.5">Rule Code</th>
                <th className="p-3.5">Rule Name</th>
                <th className="p-3.5">Format</th>
                <th className="p-3.5">Severity</th>
                <th className="p-3.5">Quality Score</th>
                <th className="p-3.5">Lifecycle Status</th>
                <th className="p-3.5">Version</th>
                <th className="p-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {rules.length > 0 ? (
                rules.map((rule) => (
                  <tr key={rule.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3.5 whitespace-nowrap">
                      <span className="px-2 py-1 rounded bg-slate-900 text-slate-200 font-bold border border-slate-700">
                        {rule.rule_code}
                      </span>
                    </td>
                    <td className="p-3.5 font-sans">
                      <div className="font-semibold text-slate-100">{rule.name}</div>
                      <span className="text-[10px] text-slate-400 font-mono">{rule.category || 'General'}</span>
                    </td>
                    <td className="p-3.5 whitespace-nowrap text-blue-400 font-bold">{rule.rule_type}</td>
                    <td className="p-3.5 whitespace-nowrap">
                      <Badge variant={rule.severity.toLowerCase() as any}>{rule.severity}</Badge>
                    </td>
                    <td className="p-3.5 whitespace-nowrap text-emerald-400 font-bold">{rule.quality_score} / 100</td>
                    <td className="p-3.5 whitespace-nowrap">
                      <Badge variant={rule.status === 'ACTIVE' ? 'success' : rule.status === 'CANDIDATE' ? 'warning' : 'neutral'}>
                        {rule.status}
                      </Badge>
                    </td>
                    <td className="p-3.5 whitespace-nowrap text-slate-400">v{rule.version}</td>
                    <td className="p-3.5 whitespace-nowrap text-right">
                      <button
                        onClick={() => setSelectedRule(rule)}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition"
                      >
                        View Rule Code
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-slate-500 font-mono">
                    No detection rules found.
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

      {/* Rule Code Modal */}
      {selectedRule && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-surface border border-slate-700 rounded-xl max-w-3xl w-full p-6 space-y-4 shadow-2xl overflow-y-auto max-h-[90vh]">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-xs font-mono text-blue-400 font-bold">{selectedRule.rule_type} RULE</span>
                <h3 className="text-base font-bold text-slate-100 mt-0.5">{selectedRule.name} ({selectedRule.rule_code})</h3>
              </div>
              <button onClick={() => setSelectedRule(null)} className="text-slate-400 hover:text-slate-200">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div>
              <span className="text-xs font-mono text-slate-400 block mb-1">Raw Rule Syntax:</span>
              <pre className="p-4 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-emerald-300 overflow-x-auto">
                {selectedRule.raw_content}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
