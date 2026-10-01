import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  AlertTriangle,
  FileSearch,
  CheckSquare,
  Fingerprint,
  Code2,
  PlaySquare,
  Activity,
  ArrowRight,
  TrendingUp,
} from 'lucide-react';
import { overviewApi, alertsApi, incidentsApi, casesApi } from '../api';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const Dashboard: React.FC = () => {
  const { data: metrics, isLoading: isMetricsLoading } = useQuery({
    queryKey: ['overviewMetrics'],
    queryFn: () => overviewApi.getOverviewMetrics(),
    refetchInterval: 10000,
  });

  const { data: recentAlerts } = useQuery({
    queryKey: ['recentAlerts'],
    queryFn: () => alertsApi.listAlerts({ page_size: 5 }),
    refetchInterval: 10000,
  });

  const { data: recentIncidents } = useQuery({
    queryKey: ['recentIncidents'],
    queryFn: () => incidentsApi.listIncidents({ page_size: 5 }),
    refetchInterval: 10000,
  });

  const { data: pendingApprovals } = useQuery({
    queryKey: ['pendingApprovals'],
    queryFn: () => casesApi.listPendingApprovals(),
    refetchInterval: 5000,
  });

  if (isMetricsLoading) return <LoadingSpinner label="Loading Executive SOC Dashboard..." />;

  const statCards = [
    {
      title: 'TOTAL ALERTS',
      value: metrics?.total_alerts || 0,
      sub: `${metrics?.critical_alerts || 0} Critical`,
      icon: <ShieldAlert className="w-5 h-5 text-amber-400" />,
      color: 'border-amber-500/20 text-amber-400',
      link: '/alerts',
    },
    {
      title: 'OPEN INCIDENTS',
      value: metrics?.open_incidents || 0,
      sub: `${metrics?.critical_incidents || 0} Critical Severity`,
      icon: <AlertTriangle className="w-5 h-5 text-red-400" />,
      color: 'border-red-500/20 text-red-400',
      link: '/incidents',
    },
    {
      title: 'ACTIVE INVESTIGATIONS',
      value: metrics?.active_investigations || 0,
      sub: 'Autonomous Pipeline Active',
      icon: <FileSearch className="w-5 h-5 text-blue-400" />,
      color: 'border-blue-500/20 text-blue-400',
      link: '/investigations',
    },
    {
      title: 'PENDING APPROVALS',
      value: metrics?.pending_approvals || 0,
      sub: 'SOAR Action Gates Pending',
      icon: <CheckSquare className="w-5 h-5 text-purple-400" />,
      color: 'border-purple-500/20 text-purple-400',
      link: '/approvals',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface border border-slate-800 p-6 rounded-2xl shadow-xl">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>AegisAI XDR</span>
            <span className="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">
              AUTONOMOUS SOC
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time Threat Triage, Autonomous Multi-Agent Investigation & Human-Governed SOAR Response.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right font-mono">
            <span className="text-xs text-slate-400 block">Avg Platform Risk Score</span>
            <span className="text-lg font-bold text-amber-400">{metrics?.average_risk_score || 0} / 100</span>
          </div>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((stat) => (
          <Link key={stat.title} to={stat.link}>
            <div className={`bg-surface border ${stat.color} p-5 rounded-xl hover:border-slate-700 transition shadow-lg`}>
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-slate-400 tracking-wider">{stat.title}</span>
                {stat.icon}
              </div>
              <div className="mt-3">
                <span className="text-3xl font-extrabold text-slate-100 font-mono">{stat.value}</span>
                <span className="text-xs text-slate-400 block mt-1">{stat.sub}</span>
              </div>
            </div>
          </Link>
        ))}
      </div>

      {/* Main Grid: Critical Alerts & Open Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Critical Alerts */}
        <Card
          title={
            <span className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              Critical Security Alerts
            </span>
          }
          action={
            <Link to="/alerts" className="text-xs text-emerald-400 hover:underline flex items-center gap-1 font-mono">
              View All Alerts <ArrowRight className="w-3 h-3" />
            </Link>
          }
        >
          <div className="space-y-3">
            {recentAlerts?.data && recentAlerts.data.length > 0 ? (
              recentAlerts.data.map((alert) => (
                <div
                  key={alert.id}
                  className="flex items-center justify-between p-3 rounded-lg bg-surfaceLight border border-slate-800/80"
                >
                  <div className="min-w-0 flex-1 mr-3">
                    <div className="flex items-center gap-2">
                      <Badge variant={alert.severity.toLowerCase() as any}>{alert.severity}</Badge>
                      <h4 className="text-xs font-semibold text-slate-200 truncate">{alert.title}</h4>
                    </div>
                    <p className="text-[11px] font-mono text-slate-400 mt-1 truncate">
                      Source: {alert.source} | Host: {alert.host || 'N/A'} | Risk: {alert.risk_score}
                    </p>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                    {new Date(alert.created_at).toLocaleTimeString()}
                  </span>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono text-center py-4">No active security alerts recorded.</p>
            )}
          </div>
        </Card>

        {/* Active Incidents */}
        <Card
          title={
            <span className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              Open Incidents Triage
            </span>
          }
          action={
            <Link to="/incidents" className="text-xs text-emerald-400 hover:underline flex items-center gap-1 font-mono">
              Incident Center <ArrowRight className="w-3 h-3" />
            </Link>
          }
        >
          <div className="space-y-3">
            {recentIncidents?.data && recentIncidents.data.length > 0 ? (
              recentIncidents.data.map((incident) => (
                <div
                  key={incident.id}
                  className="flex items-center justify-between p-3 rounded-lg bg-surfaceLight border border-slate-800/80"
                >
                  <div className="min-w-0 flex-1 mr-3">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-300 font-bold border border-slate-700">
                        {incident.incident_code}
                      </span>
                      <Badge variant={incident.severity.toLowerCase() as any}>{incident.severity}</Badge>
                      <h4 className="text-xs font-semibold text-slate-200 truncate">{incident.title}</h4>
                    </div>
                    <p className="text-[11px] font-mono text-slate-400 mt-1">
                      Status: {incident.status} | Priority: {incident.priority} | Risk: {incident.risk_score}
                    </p>
                  </div>
                  <Link
                    to={`/investigations?incident_id=${incident.id}`}
                    className="px-2.5 py-1 text-[10px] font-mono rounded bg-emerald-950 text-emerald-400 border border-emerald-800 hover:bg-emerald-900 transition"
                  >
                    Investigate
                  </Link>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono text-center py-4">No open security incidents requiring triage.</p>
            )}
          </div>
        </Card>
      </div>

      {/* Secondary Row: Pending Approvals & Security Domain Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Pending Approvals Widget */}
        <Card
          title={
            <span className="flex items-center gap-2">
              <CheckSquare className="w-4 h-4 text-purple-400" />
              Pending Human Governance Approvals
            </span>
          }
          className="lg:col-span-1"
        >
          <div className="space-y-3">
            {pendingApprovals && pendingApprovals.length > 0 ? (
              pendingApprovals.slice(0, 4).map((app) => (
                <div key={app.id} className="p-3 bg-surfaceLight border border-slate-800 rounded-lg space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-purple-300">{app.title}</span>
                    <Badge variant="warning">{app.status}</Badge>
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2">{app.description || 'Pending analyst decision'}</p>
                  <Link
                    to="/approvals"
                    className="block text-center w-full py-1 text-xs font-mono rounded bg-purple-950 text-purple-300 border border-purple-800 hover:bg-purple-900 transition"
                  >
                    Review in Approval Queue
                  </Link>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-slate-500 font-mono text-xs">
                <CheckSquare className="w-8 h-8 text-slate-700 mx-auto mb-2" />
                No pending SOAR response approvals.
              </div>
            )}
          </div>
        </Card>

        {/* Security Domains Overview Grid */}
        <Card
          title={
            <span className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-emerald-400" />
              Security Architecture Domains
            </span>
          }
          className="lg:col-span-2"
        >
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <Link to="/threat-intelligence" className="p-4 bg-surfaceLight border border-slate-800 rounded-xl hover:border-slate-700 transition">
              <Fingerprint className="w-5 h-5 text-purple-400 mb-2" />
              <h4 className="text-xs font-semibold text-slate-200">Threat Intel</h4>
              <p className="text-xl font-bold font-mono text-slate-100 mt-1">{metrics?.total_iocs || 0}</p>
              <p className="text-[10px] text-red-400 font-mono mt-0.5">{metrics?.malicious_iocs || 0} Malicious IOCs</p>
            </Link>

            <Link to="/detections" className="p-4 bg-surfaceLight border border-slate-800 rounded-xl hover:border-slate-700 transition">
              <Code2 className="w-5 h-5 text-blue-400 mb-2" />
              <h4 className="text-xs font-semibold text-slate-200">Detection Engine</h4>
              <p className="text-xl font-bold font-mono text-slate-100 mt-1">{metrics?.total_detection_rules || 0}</p>
              <p className="text-[10px] text-slate-400 font-mono mt-0.5">Rules Configured</p>
            </Link>

            <Link to="/playbooks" className="p-4 bg-surfaceLight border border-slate-800 rounded-xl hover:border-slate-700 transition">
              <PlaySquare className="w-5 h-5 text-emerald-400 mb-2" />
              <h4 className="text-xs font-semibold text-slate-200">SOAR Playbooks</h4>
              <p className="text-xl font-bold font-mono text-slate-100 mt-1">{metrics?.active_playbooks || 0}</p>
              <p className="text-[10px] text-emerald-400 font-mono mt-0.5">Active Workflows</p>
            </Link>

            <Link to="/system-health" className="p-4 bg-surfaceLight border border-slate-800 rounded-xl hover:border-slate-700 transition">
              <Activity className="w-5 h-5 text-emerald-400 mb-2" />
              <h4 className="text-xs font-semibold text-slate-200">Platform Health</h4>
              <p className="text-xl font-bold font-mono text-emerald-400 mt-1">{metrics?.system_status || 'OK'}</p>
              <p className="text-[10px] text-slate-400 font-mono mt-0.5">Services Nominal</p>
            </Link>
          </div>
        </Card>
      </div>
    </div>
  );
};
