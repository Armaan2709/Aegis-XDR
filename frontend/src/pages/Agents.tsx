import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Bot, Cpu, Shield, Search, Terminal, ArrowRight, Activity, CheckCircle2 } from 'lucide-react';
import { aiApi } from '../api';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

const AGENTS_LIST = [
  {
    name: 'AI Orchestrator',
    role: 'Central Pipeline & Agent Dispatch Engine',
    capabilities: ['Autonomous Pipeline Triage', 'State Machine Recovery', 'Human Approval Routing'],
    status: 'IDLE',
    icon: <Cpu className="w-5 h-5 text-emerald-400" />,
  },
  {
    name: 'ThreatHunterAgent',
    role: 'Hypothesis-Driven Threat Hunting',
    capabilities: ['Host Telemetry Correlation', 'Memory & Process Anomalies', 'MITRE ATT&CK Mapping'],
    status: 'IDLE',
    icon: <Search className="w-5 h-5 text-blue-400" />,
  },
  {
    name: 'DFIRInvestigatorAgent',
    role: 'Digital Forensics & Artifact Analysis',
    capabilities: ['Disk & Memory Forensics', 'Chain of Custody Tracking', 'Evidence Extraction'],
    status: 'IDLE',
    icon: <Terminal className="w-5 h-5 text-purple-400" />,
  },
  {
    name: 'ThreatIntelAnalystAgent',
    role: 'Threat Intelligence & Reputation Enrichment',
    capabilities: ['IOC Enriched Assessment', 'Feed Aggregation', 'Threat Actor Profiling'],
    status: 'IDLE',
    icon: <Shield className="w-5 h-5 text-amber-400" />,
  },
  {
    name: 'DetectionRuleGeneratorAgent',
    role: 'Automated Detection Rule Generation',
    capabilities: ['Sigma Rule Generation', 'YARA Pattern Creation', 'Rule Quality Assessment'],
    status: 'IDLE',
    icon: <Cpu className="w-5 h-5 text-cyan-400" />,
  },
  {
    name: 'IncidentCommanderAgent',
    role: 'Incident Synthesis & SOAR Action Selection',
    capabilities: ['Synthesis Report Generation', 'Containment Strategy', 'Safe Mock SOAR Trigger'],
    status: 'IDLE',
    icon: <Bot className="w-5 h-5 text-red-400" />,
  },
];

export const Agents: React.FC = () => {
  const { isLoading } = useQuery({
    queryKey: ['agentHealth'],
    queryFn: () => aiApi.getAgentHealth(),
  });

  if (isLoading) return <LoadingSpinner label="Querying AI Agent Registry..." />;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Bot className="w-5 h-5 text-emerald-400" />
          <span>Specialized AI Agent Operations & Collaboration Center</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Unified view of registered AegisAI autonomous security agents and shared InvestigationState collaboration pipeline.
        </p>
      </div>

      {/* Agents Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {AGENTS_LIST.map((agent) => (
          <div key={agent.name} className="bg-surface border border-slate-800 p-5 rounded-xl space-y-4 hover:border-slate-700 transition shadow-lg">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-slate-900 border border-slate-800 rounded-lg">{agent.icon}</div>
                <div>
                  <h3 className="text-sm font-bold text-slate-100">{agent.name}</h3>
                  <p className="text-[11px] text-slate-400 mt-0.5">{agent.role}</p>
                </div>
              </div>
              <Badge variant="success" size="sm">
                ONLINE
              </Badge>
            </div>

            <div className="space-y-1.5 pt-2 border-t border-slate-800/80">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">Agent Capabilities:</span>
              <ul className="space-y-1">
                {agent.capabilities.map((cap) => (
                  <li key={cap} className="text-xs text-slate-300 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span>{cap}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>

      {/* Multi-Agent Collaboration Flow Map */}
      <Card
        title={
          <span className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            Autonomous Multi-Agent Shared Context Collaboration Flow
          </span>
        }
      >
        <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl overflow-x-auto">
          <div className="flex items-center justify-between min-w-[750px] gap-2 py-4">
            {[
              'Threat Triage (AI Orchestrator)',
              'Host & Process Hunt (ThreatHunter)',
              'Disk Forensics (DFIR Investigator)',
              'IOC Reputation (ThreatIntel Analyst)',
              'Rule Synthesizer (Detection Generator)',
              'Containment Command (Incident Commander)',
            ].map((step, idx, arr) => (
              <React.Fragment key={step}>
                <div className="flex flex-col items-center text-center max-w-[120px]">
                  <div className="w-8 h-8 rounded-full bg-emerald-950 border border-emerald-800 text-emerald-400 font-mono font-bold text-xs flex items-center justify-center mb-2">
                    {idx + 1}
                  </div>
                  <span className="text-[11px] font-mono text-slate-300 font-medium">{step}</span>
                </div>
                {idx < arr.length - 1 && <ArrowRight className="w-4 h-4 text-slate-600 shrink-0" />}
              </React.Fragment>
            ))}
          </div>
        </div>
      </Card>
    </div>
  );
};
