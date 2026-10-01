import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { PlaySquare, ShieldAlert, Clock } from 'lucide-react';
import { playbooksApi } from '../api';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const Playbooks: React.FC = () => {
  const { data: playbooksResponse, isLoading: isPlaybooksLoading } = useQuery({
    queryKey: ['playbooksList'],
    queryFn: () => playbooksApi.listPlaybooks({ page_size: 20 }),
  });

  const { data: executionsResponse, isLoading: isExecutionsLoading } = useQuery({
    queryKey: ['executionsList'],
    queryFn: () => playbooksApi.listExecutions({ page_size: 20 }),
  });

  if (isPlaybooksLoading || isExecutionsLoading) return <LoadingSpinner label="Loading SOAR Playbooks..." />;

  const playbooks = playbooksResponse?.data || [];
  const executions = executionsResponse?.data || [];

  return (
    <div className="space-y-6">
      {/* Safe Mock Execution Safety Banner */}
      <div className="p-4 bg-amber-950/70 border border-amber-700 rounded-2xl flex items-center justify-between shadow-xl">
        <div className="flex items-center gap-3 text-amber-300">
          <ShieldAlert className="w-6 h-6 text-amber-400 shrink-0" />
          <div>
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider">
              SAFE MOCK SOAR EXECUTION ENVIRONMENT
            </h3>
            <p className="text-[11px] text-amber-200/80 mt-0.5 font-sans">
              All automated response playbooks run under safe simulation mode. Production infrastructure, firewalls, and active directory remain unmutated.
            </p>
          </div>
        </div>
        <Badge variant="warning">SIMULATED</Badge>
      </div>

      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <PlaySquare className="w-5 h-5 text-emerald-400" />
          <span>SOAR Automated Response Playbooks</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Configured orchestration playbooks, automated response steps, and execution audit history.
        </p>
      </div>

      {/* Playbooks Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {playbooks.map((pb) => (
          <div key={pb.id} className="bg-surface border border-slate-800 p-5 rounded-xl space-y-3 hover:border-slate-700 transition shadow-lg">
            <div className="flex items-start justify-between">
              <div>
                <Badge variant={pb.is_active ? 'success' : 'neutral'} size="sm">
                  {pb.status}
                </Badge>
                <h3 className="text-sm font-bold text-slate-100 mt-2">{pb.name}</h3>
              </div>
            </div>
            <p className="text-xs text-slate-400">{pb.description || 'Automated security response workflow.'}</p>
            <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 font-mono text-[10px] text-slate-500">
              <span>Category: {pb.category}</span>
              <span>Trigger: {pb.trigger_type}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Executions Log */}
      <Card
        title={
          <span className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-emerald-400" />
            Recent Playbook Execution Audit History
          </span>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead className="bg-surfaceLight border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px] tracking-wider">
              <tr>
                <th className="p-3.5">Execution ID</th>
                <th className="p-3.5">Playbook ID</th>
                <th className="p-3.5">Current Step</th>
                <th className="p-3.5">Execution Status</th>
                <th className="p-3.5 text-right">Started At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {executions.length > 0 ? (
                executions.map((ex) => (
                  <tr key={ex.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3.5 whitespace-nowrap text-slate-200">{ex.id}</td>
                    <td className="p-3.5 whitespace-nowrap text-slate-400">{ex.playbook_id}</td>
                    <td className="p-3.5 whitespace-nowrap text-slate-300">Step #{ex.current_step_index}</td>
                    <td className="p-3.5 whitespace-nowrap">
                      <Badge variant={ex.status === 'COMPLETED' ? 'success' : ex.status === 'RUNNING' ? 'info' : 'neutral'}>
                        {ex.status}
                      </Badge>
                    </td>
                    <td className="p-3.5 whitespace-nowrap text-right text-slate-500 text-[11px]">
                      {new Date(ex.started_at).toLocaleString()}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500 font-mono">
                    No playbook execution logs recorded.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
