import React from 'react';
import { clsx } from 'clsx';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'low' | 'medium' | 'high' | 'critical' | 'success' | 'warning' | 'info' | 'neutral';
  className?: string;
  size?: 'sm' | 'md';
}

export const Badge: React.FC<BadgeProps> = ({ children, variant = 'neutral', className, size = 'md' }) => {
  const variantStyles = {
    low: 'bg-emerald-950/60 text-emerald-400 border-emerald-800/50',
    medium: 'bg-amber-950/60 text-amber-400 border-amber-800/50',
    high: 'bg-orange-950/60 text-orange-400 border-orange-800/50',
    critical: 'bg-red-950/80 text-red-400 border-red-800/60 font-semibold animate-pulse',
    success: 'bg-emerald-950/60 text-emerald-400 border-emerald-800/50',
    warning: 'bg-amber-950/60 text-amber-400 border-amber-800/50',
    info: 'bg-blue-950/60 text-blue-400 border-blue-800/50',
    neutral: 'bg-slate-800 text-slate-300 border-slate-700',
  };

  const sizeStyles = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-xs font-medium',
  };

  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded-md border font-mono uppercase tracking-wider',
        variantStyles[variant],
        sizeStyles[size],
        className
      )}
    >
      {children}
    </span>
  );
};
