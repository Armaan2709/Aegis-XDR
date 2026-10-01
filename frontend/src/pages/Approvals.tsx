import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { CheckSquare, ShieldCheck, XCircle, CheckCircle2, RefreshCw, X } from 'lucide-react';
import { casesApi } from '../api';
import { CaseApproval } from '../types';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const Approvals: React.FC = () => {
  const queryClient = useQueryClient();
  const [selectedApproval, setSelectedApproval] = useState<CaseApproval | null>(null);
  const [decisionNotes, setDecisionNotes] = useState('');
  const [decisionType, setDecisionType] = useState<boolean>(true);

  const { data: pendingApprovals, isLoading, refetch } = useQuery({
    queryKey: ['pendingApprovalsList'],
    queryFn: () => casesApi.listPendingApprovals(),
    refetchInterval: 5000,
  });

  const decisionMutation = useMutation({
    mutationFn: ({ caseId, approvalId, approved, notes }: { caseId: string; approvalId: string; approved: boolean; notes: string }) =>
      casesApi.processApprovalDecision(caseId, approvalId, approved, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['pendingApprovalsList'] });
      queryClient.invalidateQueries({ queryKey: ['pendingApprovals'] });
      queryClient.invalidateQueries({ queryKey: ['overviewMetrics'] });
      setSelectedApproval(null);
      setDecisionNotes('');
    },
  });

  if (isLoading) return <LoadingSpinner label="Querying Pending Governance Approvals..." />;

  const approvals = pendingApprovals || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <CheckSquare className="w-5 h-5 text-purple-400" />
            <span>Approval Center & Human Governance Queue</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Human-in-the-Loop review gate for SOAR response execution and high-risk containment actions.
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh Queue
        </button>
      </div>

      {/* Pending Approvals Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {approvals.length > 0 ? (
          approvals.map((app) => (
            <div
              key={app.id}
              className="bg-surface border border-purple-800/40 p-5 rounded-xl space-y-4 hover:border-purple-600/60 transition shadow-xl"
            >
              <div className="flex items-start justify-between">
                <div>
                  <Badge variant="warning" size="sm">
                    PENDING HUMAN DECISION
                  </Badge>
                  <h3 className="text-sm font-bold text-slate-100 mt-2">{app.title}</h3>
                </div>
                <span className="text-[10px] font-mono text-slate-500">{new Date(app.created_at).toLocaleString()}</span>
              </div>

              <p className="text-xs text-slate-300 bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono">
                {app.description || 'SOAR Response Playbook execution requested analyst approval.'}
              </p>

              <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-xs font-mono">
                <span className="text-slate-400">Case ID: {app.case_id}</span>
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      setSelectedApproval(app);
                      setDecisionType(false);
                    }}
                    className="px-3 py-1.5 bg-red-950 text-red-400 border border-red-800 hover:bg-red-900 rounded text-xs font-bold transition flex items-center gap-1"
                  >
                    <XCircle className="w-3.5 h-3.5" /> Reject
                  </button>
                  <button
                    onClick={() => {
                      setSelectedApproval(app);
                      setDecisionType(true);
                    }}
                    className="px-3 py-1.5 bg-emerald-950 text-emerald-400 border border-emerald-800 hover:bg-emerald-900 rounded text-xs font-bold transition flex items-center gap-1"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" /> Approve Action
                  </button>
                </div>
              </div>
            </div>
          ))
        ) : (
          <Card className="col-span-2 text-center py-12">
            <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
            <h3 className="text-sm font-bold text-slate-200 font-mono">No Pending Approvals</h3>
            <p className="text-xs text-slate-400 mt-1">All SOAR containment action gates have been evaluated.</p>
          </Card>
        )}
      </div>

      {/* Governance Decision Modal */}
      {selectedApproval && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-surface border border-slate-700 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100">
                {decisionType ? 'Approve' : 'Reject'} Action: {selectedApproval.title}
              </h3>
              <button onClick={() => setSelectedApproval(null)} className="text-slate-400 hover:text-slate-200">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div>
              <label className="text-xs font-mono text-slate-400 block mb-1">Analyst Decision Rationale / Notes:</label>
              <textarea
                value={decisionNotes}
                onChange={(e) => setDecisionNotes(e.target.value)}
                rows={3}
                placeholder="Enter mandatory governance audit notes..."
                className="w-full p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-slate-600"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button onClick={() => setSelectedApproval(null)} className="px-4 py-1.5 bg-slate-800 text-slate-300 rounded text-xs font-mono">
                Cancel
              </button>
              <button
                onClick={() =>
                  decisionMutation.mutate({
                    caseId: selectedApproval.case_id,
                    approvalId: selectedApproval.id,
                    approved: decisionType,
                    notes: decisionNotes,
                  })
                }
                className={`px-4 py-1.5 rounded text-xs font-mono font-bold transition border ${
                  decisionType
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-800 hover:bg-emerald-900'
                    : 'bg-red-950 text-red-300 border-red-800 hover:bg-red-900'
                }`}
              >
                Confirm {decisionType ? 'Approval' : 'Rejection'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
