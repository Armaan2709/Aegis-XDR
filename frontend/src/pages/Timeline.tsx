import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Clock, RefreshCw } from 'lucide-react';
import { timelineApi } from '../api';
import { Card } from '../components/common/Card';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const Timeline: React.FC = () => {
  const [page] = useState(1);

  const { data: timelineResponse, isLoading, refetch } = useQuery({
    queryKey: ['timelineEvents', page],
    queryFn: () => timelineApi.getTimelineEvents({ page, page_size: 20 }),
  });

  if (isLoading) return <LoadingSpinner label="Compiling Unified Security Timeline..." />;

  const events = timelineResponse?.data || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Clock className="w-5 h-5 text-emerald-400" />
            <span>Unified Security Audit Timeline</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Chronological aggregation of alerts, AI agent discoveries, governance approvals, and SOAR executions.
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh Timeline
        </button>
      </div>

      {/* Timeline Stream */}
      <Card className="p-6">
        {events.length > 0 ? (
          <div className="relative border-l-2 border-slate-800 ml-4 space-y-6">
            {events.map((evt: any, idx: number) => (
              <div key={evt.id || idx} className="relative pl-6">
                <div className="absolute -left-[9px] top-1.5 w-4 h-4 rounded-full bg-slate-900 border border-emerald-500/50 flex items-center justify-center">
                  <div className="w-1.5 h-1.5 rounded-full bg-emerald-400"></div>
                </div>

                <div className="bg-surfaceLight border border-slate-800 p-4 rounded-xl space-y-1 hover:border-slate-700 transition">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-emerald-400 border border-slate-700 font-bold uppercase">
                      {evt.event_type || 'SECURITY_EVENT'}
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">
                      {evt.timestamp ? new Date(evt.timestamp).toLocaleString() : 'N/A'}
                    </span>
                  </div>
                  <h4 className="text-xs font-bold text-slate-100 mt-1">{evt.title || evt.summary || 'Security Event'}</h4>
                  <p className="text-xs text-slate-300 font-mono">{evt.description || evt.details || 'Event logged in telemetry stream.'}</p>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12 font-mono text-xs text-slate-500">
            No chronological timeline events recorded in active session.
          </div>
        )}
      </Card>
    </div>
  );
};
