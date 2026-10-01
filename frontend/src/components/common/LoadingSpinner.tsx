import React from 'react';

export const LoadingSpinner: React.FC<{ label?: string }> = ({ label = 'Loading SOC data...' }) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 space-y-3">
      <div className="w-8 h-8 border-4 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
      <p className="text-xs font-mono text-slate-400">{label}</p>
    </div>
  );
};
