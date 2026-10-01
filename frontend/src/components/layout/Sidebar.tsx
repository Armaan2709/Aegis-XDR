import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  AlertTriangle,
  FileSearch,
  Bot,
  Fingerprint,
  Code2,
  Layers,
  Briefcase,
  CheckSquare,
  PlaySquare,
  Clock,
  Activity,
  BarChart2,
  Zap,
} from 'lucide-react';
import { clsx } from 'clsx';

interface NavItem {
  name: string;
  path: string;
  icon: React.ReactNode;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const navSections: NavSection[] = [
  {
    title: 'COMMAND CENTER',
    items: [
      { name: 'Overview', path: '/', icon: <LayoutDashboard className="w-4 h-4" /> },
      { name: 'Demo Scenarios', path: '/demo', icon: <Zap className="w-4 h-4 text-purple-400" /> },
      { name: 'Analytics & Observability', path: '/analytics', icon: <BarChart2 className="w-4 h-4" /> },
      { name: 'Alerts', path: '/alerts', icon: <ShieldAlert className="w-4 h-4" /> },
      { name: 'Incidents', path: '/incidents', icon: <AlertTriangle className="w-4 h-4" /> },
      { name: 'Investigations', path: '/investigations', icon: <FileSearch className="w-4 h-4" /> },
    ],
  },

  {
    title: 'AI OPERATIONS',
    items: [
      { name: 'AI Agents', path: '/agents', icon: <Bot className="w-4 h-4" /> },
      { name: 'Threat Intelligence', path: '/threat-intelligence', icon: <Fingerprint className="w-4 h-4" /> },
      { name: 'Detection Engine', path: '/detections', icon: <Code2 className="w-4 h-4" /> },
      { name: 'MITRE ATT&CK', path: '/mitre', icon: <Layers className="w-4 h-4" /> },
    ],
  },
  {
    title: 'RESPONSE & SOAR',
    items: [
      { name: 'Cases', path: '/cases', icon: <Briefcase className="w-4 h-4" /> },
      { name: 'Approvals', path: '/approvals', icon: <CheckSquare className="w-4 h-4" /> },
      { name: 'Playbooks', path: '/playbooks', icon: <PlaySquare className="w-4 h-4" /> },
    ],
  },
  {
    title: 'SYSTEM & AUDIT',
    items: [
      { name: 'Unified Timeline', path: '/timeline', icon: <Clock className="w-4 h-4" /> },
      { name: 'System Health', path: '/system-health', icon: <Activity className="w-4 h-4" /> },
    ],
  },
];

export const Sidebar: React.FC = () => {
  return (
    <aside className="w-64 bg-surface border-r border-slate-800 flex flex-col h-[calc(100vh-4rem)] sticky top-16 shrink-0 overflow-y-auto">
      <div className="p-4 space-y-6">
        {navSections.map((section) => (
          <div key={section.title} className="space-y-1">
            <h4 className="px-3 text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest mb-2">
              {section.title}
            </h4>
            {section.items.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  clsx(
                    'flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition group',
                    isActive
                      ? 'bg-primary-600/10 text-emerald-400 border border-emerald-500/20 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    <span className={clsx(isActive ? 'text-emerald-400' : 'text-slate-400 group-hover:text-slate-200')}>
                      {item.icon}
                    </span>
                    <span>{item.name}</span>
                  </>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </div>
    </aside>
  );
};
