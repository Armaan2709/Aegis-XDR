import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, X, ShieldAlert, AlertTriangle, Briefcase, FileSearch, Fingerprint } from 'lucide-react';
import { alertsApi, incidentsApi, casesApi, threatIntelApi } from '../../api';

interface GlobalSearchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const GlobalSearchModal: React.FC<GlobalSearchModalProps> = ({ isOpen, onClose }) => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<Array<{ id: string; type: string; title: string; subtitle: string; link: string }>>([]);
  const [isSearching, setIsSearching] = useState(false);
  const navigate = useNavigate();

  if (!isOpen) return null;

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setIsSearching(true);
    try {
      const [alertsRes, incidentsRes, casesRes, iocRes] = await Promise.allSettled([
        alertsApi.listAlerts({ query: query.trim(), page_size: 5 }),
        incidentsApi.listIncidents({ query: query.trim(), page_size: 5 }),
        casesApi.listCases({ query: query.trim(), page_size: 5 }),
        threatIntelApi.listIOCs({ query: query.trim(), page_size: 5 }),
      ]);

      const items: Array<{ id: string; type: string; title: string; subtitle: string; link: string }> = [];

      if (alertsRes.status === 'fulfilled' && alertsRes.value?.data) {
        alertsRes.value.data.forEach((a) => {
          items.push({
            id: a.id,
            type: 'ALERT',
            title: a.title,
            subtitle: `Severity: ${a.severity} | Host: ${a.host || 'N/A'} | Status: ${a.status}`,
            link: `/alerts`,
          });
        });
      }

      if (incidentsRes.status === 'fulfilled' && incidentsRes.value?.data) {
        incidentsRes.value.data.forEach((inc) => {
          items.push({
            id: inc.id,
            type: 'INCIDENT',
            title: `${inc.incident_code}: ${inc.title}`,
            subtitle: `Priority: ${inc.priority} | Risk: ${inc.risk_score} | Status: ${inc.status}`,
            link: `/incidents`,
          });
        });
      }

      if (casesRes.status === 'fulfilled' && casesRes.value?.data) {
        casesRes.value.data.forEach((c) => {
          items.push({
            id: c.id,
            type: 'CASE',
            title: `${c.case_number}: ${c.title}`,
            subtitle: `Severity: ${c.severity} | Status: ${c.status}`,
            link: `/cases`,
          });
        });
      }

      if (iocRes.status === 'fulfilled' && iocRes.value?.data) {
        iocRes.value.data.forEach((ioc) => {
          items.push({
            id: ioc.id,
            type: 'IOC',
            title: ioc.indicator_value,
            subtitle: `Type: ${ioc.ioc_type} | Reputation: ${ioc.reputation_level} | Risk: ${ioc.risk_score}`,
            link: `/threat-intelligence`,
          });
        });
      }

      setResults(items);
    } catch (err) {
      console.error('Search error:', err);
    } finally {
      setIsSearching(false);
    }
  };

  const getItemIcon = (type: string) => {
    switch (type) {
      case 'ALERT':
        return <ShieldAlert className="w-4 h-4 text-amber-400" />;
      case 'INCIDENT':
        return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case 'CASE':
        return <Briefcase className="w-4 h-4 text-blue-400" />;
      case 'IOC':
        return <Fingerprint className="w-4 h-4 text-purple-400" />;
      default:
        return <FileSearch className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-start justify-center pt-20 px-4">
      <div className="bg-surface border border-slate-700 rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        <form onSubmit={handleSearch} className="flex items-center px-4 py-3 border-b border-slate-800 bg-surfaceLight">
          <Search className="w-5 h-5 text-slate-400 mr-3" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Global Search Alerts, Incidents, Cases, IOCs, Hosts, Users..."
            className="w-full bg-transparent text-slate-100 placeholder-slate-500 focus:outline-none font-sans text-sm"
            autoFocus
          />
          <button type="button" onClick={onClose} className="p-1 text-slate-400 hover:text-slate-200">
            <X className="w-5 h-5" />
          </button>
        </form>

        <div className="max-h-96 overflow-y-auto p-4 space-y-2">
          {isSearching ? (
            <p className="text-xs text-slate-400 text-center py-6 font-mono">Searching AegisAI XDR datastores...</p>
          ) : results.length > 0 ? (
            results.map((item) => (
              <div
                key={`${item.type}-${item.id}`}
                onClick={() => {
                  navigate(item.link);
                  onClose();
                }}
                className="flex items-start gap-3 p-3 rounded-lg hover:bg-surfaceLight cursor-pointer transition border border-transparent hover:border-slate-700"
              >
                <div className="p-2 bg-slate-900 rounded-md border border-slate-800">{getItemIcon(item.type)}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-semibold">
                      {item.type}
                    </span>
                    <h4 className="text-sm font-medium text-slate-100 truncate">{item.title}</h4>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 font-mono">{item.subtitle}</p>
                </div>
              </div>
            ))
          ) : query.trim() ? (
            <p className="text-xs text-slate-400 text-center py-6 font-mono">No matching records found for "{query}".</p>
          ) : (
            <p className="text-xs text-slate-500 text-center py-6 font-mono">
              Type a search query (e.g., "powershell", "ALT-", "CASE-", "192.168", "T1059") and press Enter.
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
