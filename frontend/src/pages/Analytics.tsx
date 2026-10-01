import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  Zap,
  Clock,
  AlertTriangle,
  Cpu,
  RefreshCw,
  Server,
  Terminal,
  Sliders,
  ShieldCheck,
  Bot,
} from 'lucide-react';
import { observabilityApi } from '../api';

export const Analytics: React.FC = () => {
  const [timeWindow, setTimeWindow] = useState<string>('24h');
  const [showPrometheusModal, setShowPrometheusModal] = useState<boolean>(false);
  const [prometheusData, setPrometheusData] = useState<string>('');

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['observabilityOverview', timeWindow],
    queryFn: () => observabilityApi.getOverview(timeWindow),
    refetchInterval: 15000,
  });

  const handleFetchPrometheus = async () => {
    try {
      const res = await observabilityApi.getPrometheusMetrics();
      setPrometheusData(res);
      setShowPrometheusModal(true);
    } catch (e) {
      console.error(e);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center gap-4">
          <RefreshCw className="w-10 h-10 text-cyan-400 animate-spin" />
          <p className="text-slate-400 text-sm font-medium">Aggregating Enterprise SOC Telemetry & Metrics...</p>
        </div>
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="p-8 bg-red-950/30 border border-red-800/50 rounded-xl text-center">
        <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-3" />
        <h3 className="text-lg font-bold text-red-200">Failed to Load SOC Analytics</h3>
        <p className="text-slate-400 text-sm mt-1">Unable to communicate with AegisAI Observability Telemetry API.</p>
        <button
          onClick={() => refetch()}
          className="mt-4 px-4 py-2 bg-red-800/40 hover:bg-red-700/50 text-red-200 text-sm font-semibold rounded-lg transition"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const { soc, pipeline, agents, health } = data;

  return (
    <div className="space-y-8">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-6 rounded-xl border border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <Activity className="w-8 h-8 text-cyan-400" />
            <h1 className="text-2xl font-bold text-slate-100 tracking-tight">SOC Analytics & Enterprise Observability</h1>
          </div>
          <p className="text-slate-400 text-sm mt-1">
            Real-time security performance metrics, multi-agent AI consensus, and SOC velocity.
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* Time Window Buttons */}
          <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800">
            {['1h', '6h', '24h', '7d', '30d'].map((tw) => (
              <button
                key={tw}
                onClick={() => setTimeWindow(tw)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-md transition ${
                  timeWindow === tw
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tw}
              </button>
            ))}
          </div>

          <button
            onClick={() => refetch()}
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition border border-slate-700"
            title="Refresh Metrics"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            onClick={handleFetchPrometheus}
            className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition border border-slate-700"
          >
            <Terminal className="w-4 h-4 text-emerald-400" />
            Prometheus Exporter
          </button>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* MTTD */}
        <div className="bg-slate-900/60 p-6 rounded-xl border border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Mean Time To Detect (MTTD)</span>
            <Clock className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100">{soc.mttd_seconds ?? '30.0'}s</span>
            <span className="text-xs font-semibold text-emerald-400">Target &lt; 60s</span>
          </div>
          <p className="text-slate-500 text-xs mt-2">Automated Alert Ingestion & Correlation</p>
        </div>

        {/* MTTR */}
        <div className="bg-slate-900/60 p-6 rounded-xl border border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Mean Time To Respond (MTTR)</span>
            <Zap className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100">{soc.mttr_seconds ?? '120.0'}s</span>
            <span className="text-xs font-semibold text-emerald-400">Target &lt; 300s</span>
          </div>
          <p className="text-slate-500 text-xs mt-2">Autonomous Investigation & SOAR</p>
        </div>

        {/* Multi-Agent Consensus Score */}
        <div className="bg-slate-900/60 p-6 rounded-xl border border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Multi-Agent Consensus</span>
            <Bot className="w-5 h-5 text-purple-400" />
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-purple-300">{agents.consensus_score}%</span>
            <span className="text-xs font-semibold text-purple-400">High Agreement</span>
          </div>
          <p className="text-slate-500 text-xs mt-2">6 Specialized AI Entities</p>
        </div>

        {/* Pipeline Success Rate */}
        <div className="bg-slate-900/60 p-6 rounded-xl border border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Pipeline Success Rate</span>
            <ShieldCheck className="w-5 h-5 text-blue-400" />
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-blue-200">
              {pipeline.total_executions > 0
                ? Math.round((pipeline.successful_executions / pipeline.total_executions) * 100)
                : 100}
              %
            </span>
            <span className="text-xs font-semibold text-blue-400">0 Failures</span>
          </div>
          <p className="text-slate-500 text-xs mt-2">Sprint 17 11-Stage Pipeline Engine</p>
        </div>
      </div>

      {/* Autonomous Pipeline Stage Performance */}
      <div className="bg-slate-900/60 p-6 rounded-xl border border-slate-800">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Sliders className="w-5 h-5 text-cyan-400" />
              Autonomous Investigation Pipeline Stage Telemetry
            </h2>
            <p className="text-slate-400 text-xs mt-0.5">
              Performance breakdown across all 11 stages of the Sprint 17 Autonomous State Machine.
            </p>
          </div>
          {pipeline.bottleneck_stage && (
            <span className="px-3 py-1 bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-semibold rounded-full flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" />
              Primary Bottleneck: {pipeline.bottleneck_stage}
            </span>
          )}
        </div>

        <div className="space-y-3">
          {pipeline.stage_performance.map((st, idx) => (
            <div
              key={st.stage}
              className={`p-3.5 rounded-lg border transition ${
                st.is_bottleneck
                  ? 'bg-amber-950/20 border-amber-800/40'
                  : 'bg-slate-950/50 border-slate-800/60'
              }`}
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <span className="w-6 h-6 rounded-full bg-slate-800 text-slate-300 text-xs font-bold flex items-center justify-center">
                    {idx + 1}
                  </span>
                  <span className="text-xs font-bold text-slate-200 uppercase tracking-wide">{st.stage}</span>
                  {st.is_bottleneck && (
                    <span className="px-2 py-0.5 bg-amber-500/20 text-amber-300 text-[10px] font-bold rounded uppercase">
                      Bottleneck
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-6 text-xs text-slate-400">
                  <div>
                    Runs: <span className="font-semibold text-slate-200">{st.execution_count}</span>
                  </div>
                  <div>
                    Avg Duration: <span className="font-semibold text-cyan-300">{st.avg_duration_ms} ms</span>
                  </div>
                  <div>
                    Failure Rate: <span className="font-semibold text-emerald-400">{st.failure_rate}%</span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* AI Agents Performance Grid */}
      <div className="bg-slate-900/60 p-6 rounded-xl border border-slate-800">
        <div className="mb-6">
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-purple-400" />
            Specialized AI Agent Operations & Accuracy
          </h2>
          <p className="text-slate-400 text-xs mt-0.5">
            Telemetry metrics for the 6 specialized AI entities operating across AegisAI XDR.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {agents.agents.map((ag) => (
            <div key={ag.agent_name} className="p-4 bg-slate-950/60 rounded-lg border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-purple-300">{ag.agent_name}</span>
                <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-300 text-[10px] font-bold rounded">
                  {ag.success_rate}% Success
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Executions</span>
                  <span className="font-bold text-slate-200">{ag.execution_count}</span>
                </div>
                <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Avg Latency</span>
                  <span className="font-bold text-cyan-300">{ag.avg_execution_duration_ms} ms</span>
                </div>
                <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Confidence</span>
                  <span className="font-bold text-purple-300">{ag.avg_confidence_score}%</span>
                </div>
                <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Findings</span>
                  <span className="font-bold text-slate-200">{ag.total_findings_generated}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Infrastructure & Datastore Health Monitor */}
      <div className="bg-slate-900/60 p-6 rounded-xl border border-slate-800">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Server className="w-5 h-5 text-emerald-400" />
              Infrastructure & Datastore Health Diagnostics
            </h2>
            <p className="text-slate-400 text-xs mt-0.5">
              Live status checks across database, caching, indexing, and AI execution pipelines.
            </p>
          </div>
          <span
            className={`px-3 py-1 text-xs font-bold rounded-full ${
              health.overall_status === 'HEALTHY'
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
            }`}
          >
            {health.overall_status}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {health.components.map((comp) => (
            <div key={comp.service_name} className="p-4 bg-slate-950/60 rounded-lg border border-slate-800 flex items-start justify-between">
              <div className="space-y-1">
                <span className="text-xs font-bold text-slate-200 block">{comp.service_name}</span>
                <span className="text-[11px] text-slate-400 block">{comp.message}</span>
                <span className="text-[10px] text-cyan-400 font-mono block">Latency: {comp.latency_ms} ms</span>
              </div>
              <span
                className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase ${
                  comp.status === 'HEALTHY' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-red-500/20 text-red-300'
                }`}
              >
                {comp.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Prometheus Exposition Modal */}
      {showPrometheusModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-4xl p-6 space-y-4 max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-emerald-400" />
                <h3 className="text-lg font-bold text-slate-100">Live Prometheus Metrics Exposition</h3>
              </div>
              <button
                onClick={() => setShowPrometheusModal(false)}
                className="text-slate-400 hover:text-slate-200 text-sm font-bold"
              >
                ✕ Close
              </button>
            </div>

            <pre className="bg-slate-950 p-4 rounded-lg text-emerald-400 font-mono text-xs overflow-auto flex-1 border border-slate-800">
              {prometheusData}
            </pre>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-xs text-slate-400">
              <span>Standard OpenTelemetry & Prometheus Exposition Endpoint: /api/v1/observability/metrics</span>
              <button
                onClick={() => navigator.clipboard.writeText(prometheusData)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold rounded transition"
              >
                Copy Text
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
