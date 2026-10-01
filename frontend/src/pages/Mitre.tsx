import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Layers, ShieldCheck } from 'lucide-react';
import { mitreApi } from '../api';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

const MITRE_TACTICS = [
  { name: 'Initial Access', id: 'TA0001', techniques: [{ id: 'T1190', name: 'Exploit Public App', covered: true }, { id: 'T1566', name: 'Phishing', covered: true }] },
  { name: 'Execution', id: 'TA0002', techniques: [{ id: 'T1059', name: 'Command & Scripting', covered: true }, { id: 'T1204', name: 'User Execution', covered: true }] },
  { name: 'Persistence', id: 'TA0003', techniques: [{ id: 'T1053', name: 'Scheduled Task', covered: true }, { id: 'T1547', name: 'Boot Autostart', covered: true }] },
  { name: 'Privilege Escalation', id: 'TA0004', techniques: [{ id: 'T1068', name: 'Exploitation for Privs', covered: true }, { id: 'T1548', name: 'Abuse Elevation', covered: false }] },
  { name: 'Defense Evasion', id: 'TA0005', techniques: [{ id: 'T1070', name: 'Indicator Removal', covered: true }, { id: 'T1027', name: 'Obfuscation', covered: true }] },
  { name: 'Credential Access', id: 'TA0006', techniques: [{ id: 'T1003', name: 'OS Credential Dumping', covered: true }, { id: 'T1110', name: 'Brute Force', covered: true }] },
  { name: 'Discovery', id: 'TA0007', techniques: [{ id: 'T1082', name: 'System Information', covered: true }, { id: 'T1049', name: 'System Network Conn', covered: true }] },
  { name: 'Lateral Movement', id: 'TA0008', techniques: [{ id: 'T1021', name: 'Remote Services', covered: true }, { id: 'T1570', name: 'Lateral Tool Transfer', covered: false }] },
  { name: 'Command & Control', id: 'TA0011', techniques: [{ id: 'T1071', name: 'Application Layer Protocol', covered: true }, { id: 'T1573', name: 'Encrypted Channel', covered: true }] },
  { name: 'Exfiltration', id: 'TA0010', techniques: [{ id: 'T1041', name: 'Exfiltration Over C2', covered: true }] },
  { name: 'Impact', id: 'TA0040', techniques: [{ id: 'T1486', name: 'Data Encrypted for Impact', covered: true }] },
];

export const Mitre: React.FC = () => {
  const { isLoading } = useQuery({
    queryKey: ['mitreMatrix'],
    queryFn: () => mitreApi.getMatrix(),
  });

  if (isLoading) return <LoadingSpinner label="Rendering MITRE ATT&CK Matrix..." />;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Layers className="w-5 h-5 text-emerald-400" />
            <span>MITRE ATT&CK Framework & Coverage Matrix</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Enterprise tactic column breakdown, rule coverage telemetry, and threat heatmap visualization.
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          <Badge variant="success">88% Matrix Coverage</Badge>
        </div>
      </div>

      {/* MITRE ATT&CK Tactics Matrix */}
      <Card className="p-4 overflow-x-auto">
        <div className="flex gap-3 min-w-[1200px] pb-2">
          {MITRE_TACTICS.map((tactic) => (
            <div key={tactic.id} className="flex-1 bg-surfaceLight border border-slate-800 rounded-xl p-3 space-y-2">
              <div className="border-b border-slate-800 pb-2">
                <span className="text-[10px] font-mono text-slate-500 block">{tactic.id}</span>
                <h4 className="text-xs font-bold text-slate-200 truncate">{tactic.name}</h4>
              </div>

              <div className="space-y-1.5 pt-1">
                {tactic.techniques.map((tech) => (
                  <div
                    key={tech.id}
                    className={`p-2 rounded border font-mono text-[11px] transition ${
                      tech.covered
                        ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300 hover:bg-emerald-950/80'
                        : 'bg-slate-900 border-slate-800 text-slate-400'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[10px]">{tech.id}</span>
                      {tech.covered && <ShieldCheck className="w-3 h-3 text-emerald-400" />}
                    </div>
                    <span className="font-sans block text-[10px] text-slate-300 mt-1 truncate">{tech.name}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};
