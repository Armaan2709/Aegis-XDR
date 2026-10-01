import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  FileSearch,
  Play,
  XCircle,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Clock,
  ShieldCheck,
  Bot,
} from 'lucide-react';
import { investigationsApi, pipelineApi } from '../api';
import { PipelineStage, PipelineContext } from '../types';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

const PIPELINE_STAGES: { stage: PipelineStage; label: string; agent: string }[] = [
  { stage: 'TRIAGING', label: 'Alert Triage & Priority', agent: 'AI Orchestrator' },
  { stage: 'CORRELATING', label: 'Graph Threat Correlation', agent: 'Correlation Engine' },
  { stage: 'INVESTIGATION_STARTED', label: 'State Initialization', agent: 'AI Orchestrator' },
  { stage: 'THREAT_HUNTING', label: 'Threat Hunting Agent', agent: 'ThreatHunterAgent' },
  { stage: 'DFIR_ANALYSIS', label: 'DFIR Forensic Investigator', agent: 'DFIRInvestigatorAgent' },
  { stage: 'THREAT_INTELLIGENCE', label: 'Threat Intel Enriched Analysis', agent: 'ThreatIntelAnalystAgent' },
  { stage: 'DETECTION_GENERATION', label: 'Rule Generation', agent: 'DetectionGeneratorAgent' },
  { stage: 'INCIDENT_SYNTHESIS', label: 'Incident Commander Synthesis', agent: 'IncidentCommanderAgent' },
  { stage: 'AWAITING_REVIEW', label: 'Human Governance Review Gate', agent: 'CaseApproval Policy' },
  { stage: 'RESPONSE_EXECUTING', label: 'SOAR Safe Mock Execution', agent: 'Playbook Engine' },
  { stage: 'COMPLETED', label: 'Investigation Finalized', agent: 'AI Orchestrator' },
];

export const Investigations: React.FC = () => {
  const [searchParams] = useSearchParams();
  const incidentIdParam = searchParams.get('incident_id');
  const queryClient = useQueryClient();

  const [selectedInvestigationId, setSelectedInvestigationId] = useState<string | null>(null);

  const { data: listResponse, isLoading: isListLoading } = useQuery({
    queryKey: ['investigationsList'],
    queryFn: () => investigationsApi.listInvestigations({ page_size: 20 }),
  });

  const investigations = listResponse?.data || [];

  // Auto select first investigation or matching incident investigation
  useEffect(() => {
    if (investigations.length > 0 && !selectedInvestigationId) {
      if (incidentIdParam) {
        const found = investigations.find((inv) => inv.incident_id === incidentIdParam);
        if (found) {
          setSelectedInvestigationId(found.id);
          return;
        }
      }
      setSelectedInvestigationId(investigations[0].id);
    }
  }, [investigations, incidentIdParam, selectedInvestigationId]);

  const {
    data: pipelineContext,
    isLoading: isPipelineLoading,
    refetch: refetchPipeline,
  } = useQuery({
    queryKey: ['pipelineStatus', selectedInvestigationId],
    queryFn: () => pipelineApi.getPipelineStatus(selectedInvestigationId!),
    enabled: !!selectedInvestigationId,
    refetchInterval: (query) => {
      const data = query.state.data as PipelineContext | undefined;
      return data?.status === 'RUNNING' || data?.status === 'AWAITING_APPROVAL' ? 2000 : false;
    },
  });

  const runMutation = useMutation({
    mutationFn: (id: string) => pipelineApi.runPipeline(id, { auto_approve_routine: false }),
    onSuccess: () => {
      refetchPipeline();
      queryClient.invalidateQueries({ queryKey: ['overviewMetrics'] });
    },
  });

  const cancelMutation = useMutation({
    mutationFn: (id: string) => pipelineApi.cancelPipeline(id),
    onSuccess: () => {
      refetchPipeline();
    },
  });

  if (isListLoading) return <LoadingSpinner label="Loading Investigations..." />;

  const currentInvestigation = investigations.find((i) => i.id === selectedInvestigationId);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileSearch className="w-5 h-5 text-blue-400" />
            <span>Autonomous Pipeline & Investigation Center</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Sprint 17 Deterministic 11-Stage Pipeline visualizer with AI agents, recovery state machine, and governance gate.
          </p>
        </div>

        {selectedInvestigationId && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetchPipeline()}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Refresh Pipeline
            </button>

            {pipelineContext?.status !== 'RUNNING' && (
              <button
                onClick={() => runMutation.mutate(selectedInvestigationId)}
                className="px-3.5 py-1.5 bg-emerald-950 text-emerald-400 border border-emerald-800 hover:bg-emerald-900 rounded-lg text-xs font-mono font-bold transition flex items-center gap-1.5"
              >
                <Play className="w-3.5 h-3.5 fill-emerald-400" /> Run Pipeline
              </button>
            )}

            {pipelineContext?.status === 'RUNNING' && (
              <button
                onClick={() => cancelMutation.mutate(selectedInvestigationId)}
                className="px-3 py-1.5 bg-red-950 text-red-400 border border-red-800 hover:bg-red-900 rounded-lg text-xs font-mono transition flex items-center gap-1.5"
              >
                <XCircle className="w-3.5 h-3.5" /> Abort Pipeline
              </button>
            )}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left Side: Investigation Selector */}
        <Card title="Investigation Sessions" className="lg:col-span-1 p-4">
          <div className="space-y-2">
            {investigations.map((inv) => (
              <div
                key={inv.id}
                onClick={() => setSelectedInvestigationId(inv.id)}
                className={`p-3 rounded-lg border cursor-pointer transition ${
                  selectedInvestigationId === inv.id
                    ? 'bg-primary-600/10 border-emerald-500/50 text-emerald-300'
                    : 'bg-surfaceLight border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold font-mono">{inv.investigation_code}</span>
                  <Badge size="sm" variant={inv.status === 'ACTIVE' ? 'info' : 'neutral'}>
                    {inv.status}
                  </Badge>
                </div>
                <p className="text-xs font-semibold mt-1 truncate">{inv.title}</p>
                <p className="text-[10px] font-mono text-slate-500 mt-1">{new Date(inv.created_at).toLocaleString()}</p>
              </div>
            ))}
          </div>
        </Card>

        {/* Right Side: 11-Stage Pipeline Visualizer */}
        <Card
          title={
            <div className="flex items-center justify-between w-full">
              <span className="flex items-center gap-2 text-sm">
                <Bot className="w-4 h-4 text-emerald-400" />
                Pipeline Execution: {currentInvestigation?.investigation_code || 'N/A'}
              </span>
              {pipelineContext && (
                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="text-slate-400">Status:</span>
                  <Badge
                    variant={
                      pipelineContext.status === 'COMPLETED'
                        ? 'success'
                        : pipelineContext.status === 'RUNNING'
                        ? 'info'
                        : pipelineContext.status === 'AWAITING_APPROVAL'
                        ? 'warning'
                        : 'neutral'
                    }
                  >
                    {pipelineContext.status}
                  </Badge>
                </div>
              )}
            </div>
          }
          className="lg:col-span-3"
        >
          {isPipelineLoading ? (
            <LoadingSpinner label="Fetching Stage Results..." />
          ) : pipelineContext ? (
            <div className="space-y-4">
              {/* Human Governance Warning if Awaiting Approval */}
              {pipelineContext.status === 'AWAITING_APPROVAL' && (
                <div className="p-4 bg-amber-950/60 border border-amber-800/80 rounded-xl flex items-center justify-between">
                  <div className="flex items-center gap-3 text-amber-300">
                    <ShieldCheck className="w-6 h-6 text-amber-400 shrink-0" />
                    <div>
                      <h4 className="text-xs font-bold font-mono">HUMAN GOVERNANCE APPROVAL REQUIRED</h4>
                      <p className="text-[11px] text-amber-200/80 mt-0.5">
                        Response Execution Stage halted pending analyst review. CaseApproval record generated.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* 11 Pipeline Stage Steps */}
              <div className="relative border-l-2 border-slate-800 ml-4 space-y-4 my-2">
                {PIPELINE_STAGES.map((st, idx) => {
                  const stageResult = pipelineContext.stage_results?.[st.stage];
                  const isCurrent = pipelineContext.current_stage === st.stage;

                  let statusIcon = <Clock className="w-4 h-4 text-slate-600" />;
                  let nodeBorder = 'border-slate-800 bg-slate-900';

                  if (stageResult?.status === 'SUCCESS') {
                    statusIcon = <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
                    nodeBorder = 'border-emerald-500/50 bg-emerald-950/20';
                  } else if (stageResult?.status === 'FAILURE') {
                    statusIcon = <AlertCircle className="w-4 h-4 text-red-400" />;
                    nodeBorder = 'border-red-500/50 bg-red-950/20';
                  } else if (isCurrent && pipelineContext.status === 'RUNNING') {
                    statusIcon = <RefreshCw className="w-4 h-4 text-blue-400 animate-spin" />;
                    nodeBorder = 'border-blue-500/50 bg-blue-950/30';
                  }

                  return (
                    <div key={st.stage} className="relative pl-6">
                      <div className={`absolute -left-[9px] top-1.5 w-4 h-4 rounded-full border ${nodeBorder} flex items-center justify-center`}>
                        {statusIcon}
                      </div>

                      <div className={`p-3 rounded-lg border transition ${nodeBorder}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-mono px-1.5 py-0.5 bg-slate-900 border border-slate-700 rounded text-slate-300">
                              STAGE {idx + 1}
                            </span>
                            <h4 className="text-xs font-bold text-slate-200">{st.label}</h4>
                            <span className="text-[10px] font-mono text-purple-400">({st.agent})</span>
                          </div>

                          {stageResult && (
                            <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400">
                              {stageResult.duration_ms && <span>{stageResult.duration_ms}ms</span>}
                              <Badge size="sm" variant={stageResult.status === 'SUCCESS' ? 'success' : 'neutral'}>
                                {stageResult.status}
                              </Badge>
                            </div>
                          )}
                        </div>

                        {/* Error details if failed */}
                        {stageResult?.error_message && (
                          <div className="mt-2 p-2 bg-red-950/60 border border-red-900 rounded text-[11px] font-mono text-red-300">
                            Error: {stageResult.error_message}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            <div className="text-center py-12 font-mono text-xs text-slate-500">
              Select an investigation session to render the autonomous pipeline state machine.
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};
