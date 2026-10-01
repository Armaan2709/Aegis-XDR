import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Play,
  ShieldAlert,
  Bot,
  CheckCircle2,
  AlertCircle,
  CheckSquare,
  ShieldCheck,
  RefreshCw,
  Zap,
  Terminal,
  Cpu,
} from 'lucide-react';
import { demoApi } from '../api';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const DemoScenarios: React.FC = () => {
  const queryClient = useQueryClient();
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('credential_compromise');
  const [autoApprove, setAutoApprove] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'pipeline' | 'findings' | 'assertions' | 'report'>('pipeline');

  const { data: scenarios, isLoading: isScenariosLoading } = useQuery({
    queryKey: ['demoScenariosList'],
    queryFn: () => demoApi.listScenarios(),
  });

  const { data: executionResult, isLoading: isResultLoading, refetch: refetchResult } = useQuery({
    queryKey: ['demoScenarioResult', selectedScenarioId],
    queryFn: () => demoApi.getScenarioResult(selectedScenarioId),
    enabled: !!selectedScenarioId,
  });

  const { data: reportData } = useQuery({
    queryKey: ['demoScenarioReport', selectedScenarioId],
    queryFn: () => demoApi.getScenarioReport(selectedScenarioId),
    enabled: !!selectedScenarioId && activeTab === 'report',
  });

  const runMutation = useMutation({
    mutationFn: () => demoApi.runScenario(selectedScenarioId, { auto_approve: autoApprove }),
    onSuccess: () => {
      refetchResult();
      queryClient.invalidateQueries({ queryKey: ['overviewMetrics'] });
    },
  });

  const approveMutation = useMutation({
    mutationFn: () => demoApi.runScenario(selectedScenarioId, { auto_approve: true }),
    onSuccess: () => {
      refetchResult();
    },
  });

  if (isScenariosLoading) return <LoadingSpinner label="Initializing Synthetic Demonstration Framework..." />;

  const currentScenario = (scenarios || []).find((s: any) => s.scenario_id === selectedScenarioId);

  return (
    <div className="space-y-6">
      {/* Safety Isolation Banners */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 bg-purple-950/60 border border-purple-800 rounded-2xl flex items-center justify-between shadow-xl">
          <div className="flex items-center gap-3 text-purple-300">
            <Zap className="w-6 h-6 text-purple-400 shrink-0" />
            <div>
              <h3 className="text-xs font-bold font-mono uppercase tracking-wider">
                SYNTHETIC SECURITY SCENARIO ENVIRONMENT
              </h3>
              <p className="text-[11px] text-purple-200/80 mt-0.5 font-sans">
                Deterministic security attack vectors operating over synthetic telemetry feeds. Zero malware execution.
              </p>
            </div>
          </div>
          <Badge variant="info">SYNTHETIC</Badge>
        </div>

        <div className="p-4 bg-amber-950/60 border border-amber-800 rounded-2xl flex items-center justify-between shadow-xl">
          <div className="flex items-center gap-3 text-amber-300">
            <ShieldAlert className="w-6 h-6 text-amber-400 shrink-0" />
            <div>
              <h3 className="text-xs font-bold font-mono uppercase tracking-wider">
                SAFE MOCK SOAR EXECUTION BOUNDARY
              </h3>
              <p className="text-[11px] text-amber-200/80 mt-0.5 font-sans">
                Response actions execute in safe simulation mode. CaseApproval governance gate remains mandatory.
              </p>
            </div>
          </div>
          <Badge variant="warning">SAFE MOCK</Badge>
        </div>
      </div>

      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Bot className="w-5 h-5 text-emerald-400" />
            <span>End-to-End Security Validation & SOC Demonstration</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Reproducible SOC scenarios demonstrating full pipeline capabilities from raw telemetry to mock SOAR response.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
            <input
              type="checkbox"
              checked={autoApprove}
              onChange={(e) => setAutoApprove(e.target.checked)}
              className="rounded border-slate-700 bg-slate-800 text-emerald-500 focus:ring-0"
            />
            Auto-Approve Governance Gate
          </label>

          <button
            onClick={() => runMutation.mutate()}
            disabled={runMutation.isPending}
            className="px-4 py-2 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 rounded-xl text-xs font-mono font-bold transition flex items-center gap-2 shadow-lg disabled:opacity-50"
          >
            {runMutation.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-emerald-400" />}
            RUN SYNTHETIC SCENARIO
          </button>
        </div>
      </div>

      {/* Scenario Selection Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {(scenarios || []).map((scen: any) => {
          const isSelected = selectedScenarioId === scen.scenario_id;
          return (
            <div
              key={scen.scenario_id}
              onClick={() => setSelectedScenarioId(scen.scenario_id)}
              className={`p-5 rounded-2xl border cursor-pointer transition shadow-lg flex flex-col justify-between ${
                isSelected
                  ? 'bg-emerald-950/20 border-emerald-500/60 ring-1 ring-emerald-500/30'
                  : 'bg-surface border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Badge variant={scen.expected_severity === 'CRITICAL' ? 'critical' : 'warning'} size="sm">
                    {scen.expected_severity}
                  </Badge>
                  <span className="text-[10px] font-mono text-slate-500">{scen.scenario_id}</span>
                </div>
                <h3 className="text-sm font-bold text-slate-100">{scen.name}</h3>
                <p className="text-xs text-slate-400 leading-relaxed">{scen.description}</p>
              </div>

              <div className="pt-4 border-t border-slate-800/80 mt-4 space-y-2">
                <div className="flex flex-wrap gap-1">
                  {scen.attack_phases.map((ph: string, idx: number) => (
                    <span key={idx} className="text-[9px] font-mono bg-slate-900 border border-slate-800 text-slate-400 px-1.5 py-0.5 rounded">
                      {ph}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Execution Results View Tabs */}
      <Card
        title={
          <div className="flex items-center justify-between w-full">
            <span className="flex items-center gap-2 text-sm font-bold">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Scenario Execution: {currentScenario?.name || 'Selected Scenario'}
            </span>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setActiveTab('pipeline')}
                className={`px-3 py-1 text-xs font-mono rounded-lg transition ${
                  activeTab === 'pipeline' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                11-Stage Pipeline
              </button>
              <button
                onClick={() => setActiveTab('findings')}
                className={`px-3 py-1 text-xs font-mono rounded-lg transition ${
                  activeTab === 'findings' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                AI Agent Findings
              </button>
              <button
                onClick={() => setActiveTab('assertions')}
                className={`px-3 py-1 text-xs font-mono rounded-lg transition ${
                  activeTab === 'assertions' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                20-Point Assertions ({executionResult?.assertions_passed || 0}/20)
              </button>
              <button
                onClick={() => setActiveTab('report')}
                className={`px-3 py-1 text-xs font-mono rounded-lg transition ${
                  activeTab === 'report' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Structured Report
              </button>
            </div>
          </div>
        }
      >
        {isResultLoading ? (
          <LoadingSpinner label="Compiling Execution State..." />
        ) : executionResult ? (
          <div className="space-y-6">
            {/* CaseApproval Human Review Gate Warning Banner */}
            {executionResult.approval_status === 'PENDING' && (
              <div className="p-4 bg-amber-950/70 border border-amber-800 rounded-xl flex items-center justify-between">
                <div className="flex items-center gap-3 text-amber-300">
                  <ShieldCheck className="w-6 h-6 text-amber-400 shrink-0" />
                  <div>
                    <h4 className="text-xs font-bold font-mono">HUMAN GOVERNANCE APPROVAL REQUIRED</h4>
                    <p className="text-[11px] text-amber-200/80 mt-0.5">
                      CaseApproval record pending analyst review. SOAR response actions remain safely paused until granted.
                    </p>
                  </div>
                </div>

                <button
                  onClick={() => approveMutation.mutate()}
                  className="px-3.5 py-1.5 bg-amber-900 hover:bg-amber-800 text-amber-100 border border-amber-700 rounded-lg text-xs font-mono font-bold transition flex items-center gap-1.5"
                >
                  <CheckSquare className="w-4 h-4" />
                  APPROVE SIMULATED SOAR
                </button>
              </div>
            )}

            {/* TAB 1: 11-Stage Pipeline View */}
            {activeTab === 'pipeline' && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-slate-900/60 rounded-xl border border-slate-800 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block">Risk Score</span>
                    <span className="text-amber-400 font-bold text-sm">{executionResult.risk_score} / 100</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Severity</span>
                    <Badge variant={executionResult.severity === 'CRITICAL' ? 'critical' : 'warning'} size="sm">
                      {executionResult.severity}
                    </Badge>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Approval Status</span>
                    <Badge variant={executionResult.approval_status === 'APPROVED' ? 'success' : 'neutral'} size="sm">
                      {executionResult.approval_status}
                    </Badge>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Execution Mode</span>
                    <span className="text-emerald-400 font-bold">{executionResult.soar_execution_mode}</span>
                  </div>
                </div>

                <div className="border-l-2 border-slate-800 ml-4 space-y-4 my-2">
                  {[
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
                  ].map((st, idx) => (
                    <div key={st.stage} className="relative pl-6">
                      <div className="absolute -left-[9px] top-1.5 w-4 h-4 rounded-full border border-emerald-500/50 bg-emerald-950/20 flex items-center justify-center">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      </div>
                      <div className="p-3 bg-surfaceLight border border-slate-800 rounded-lg flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono px-1.5 py-0.5 bg-slate-900 border border-slate-700 rounded text-slate-300">
                            STAGE {idx + 1}
                          </span>
                          <h4 className="text-xs font-bold text-slate-200">{st.label}</h4>
                          <span className="text-[10px] font-mono text-purple-400">({st.agent})</span>
                        </div>
                        <Badge size="sm" variant="success">SUCCESS</Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB 2: AI Agent Findings */}
            {activeTab === 'findings' && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.entries(executionResult.agent_findings).map(([agent, finding]: [string, any]) => (
                  <div key={agent} className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
                    <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
                      <Cpu className="w-4 h-4 text-purple-400" />
                      <h4 className="text-xs font-bold text-slate-200">{agent}</h4>
                    </div>
                    <pre className="text-[11px] font-mono text-slate-300 bg-slate-950 p-3 rounded-lg overflow-x-auto">
                      {JSON.stringify(finding, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            )}

            {/* TAB 3: 20-Point Assertions */}
            {activeTab === 'assertions' && (
              <div className="space-y-2">
                {executionResult.assertions.map((a: any) => (
                  <div key={a.assertion_id} className="p-3 bg-slate-900/40 border border-slate-800 rounded-lg flex items-center justify-between font-mono text-xs">
                    <div className="flex items-center gap-3">
                      {a.passed ? <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" /> : <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />}
                      <span className="text-slate-200">Assertion #{a.assertion_id}: {a.name}</span>
                    </div>
                    <span className="text-[11px] text-slate-400">{a.details}</span>
                  </div>
                ))}
              </div>
            )}

            {/* TAB 4: Structured Report */}
            {activeTab === 'report' && (
              <div className="space-y-4">
                {reportData ? (
                  <div className="space-y-4 text-xs font-mono">
                    <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
                      <h4 className="font-bold text-slate-100 uppercase text-[10px]">Overview</h4>
                      <p className="text-slate-300 font-sans text-xs">{reportData.overview}</p>
                    </div>

                    <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
                      <h4 className="font-bold text-slate-100 uppercase text-[10px]">Observed Telemetry</h4>
                      <div className="space-y-1">
                        {reportData.observed_telemetry.map((t: any, idx: number) => (
                          <div key={idx} className="flex items-center justify-between p-2 bg-slate-950 rounded border border-slate-800">
                            <span className="text-emerald-300 font-bold">{t.item}</span>
                            <Badge variant="info" size="sm">{t.tag}</Badge>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <LoadingSpinner label="Generating Report..." />
                )}
              </div>
            )}
          </div>
        ) : (
          <div className="text-center py-12 font-mono text-xs text-slate-500">
            Select a synthetic scenario and click "RUN SYNTHETIC SCENARIO" to observe the pipeline.
          </div>
        )}
      </Card>
    </div>
  );
};
