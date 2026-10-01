import React from 'react';
import { clsx } from 'clsx';

interface CardProps {
  title?: React.ReactNode;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export const Card: React.FC<CardProps> = ({ title, subtitle, action, children, className }) => {
  return (
    <div className={clsx('bg-surface border border-slate-800 rounded-xl p-5 shadow-lg', className)}>
      {(title || action) && (
        <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800/80">
          <div>
            {typeof title === 'string' ? (
              <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">{title}</h3>
            ) : (
              title
            )}
            {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      {children}
    </div>
  );
};
