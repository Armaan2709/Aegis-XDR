import React, { useState } from 'react';
import { Search, Shield, Activity, LogOut } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { GlobalSearchModal } from '../common/GlobalSearchModal';

export const Header: React.FC = () => {
  const { user, logout } = useAuth();
  const [isSearchOpen, setIsSearchOpen] = useState(false);

  return (
    <>
      <header className="h-16 bg-surface/90 backdrop-blur border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-30">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-emerald-400 font-mono text-sm font-semibold tracking-wider">
            <Shield className="w-5 h-5 text-emerald-500 fill-emerald-500/20" />
            <span>AEGIS-XDR</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400 font-normal text-xs uppercase">SOC Command Center</span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Global Search Trigger Button */}
          <button
            onClick={() => setIsSearchOpen(true)}
            className="flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs font-mono transition"
          >
            <Search className="w-4 h-4 text-slate-400" />
            <span>Search entities (Ctrl+K)...</span>
            <kbd className="bg-slate-800 text-slate-400 border border-slate-700 px-1.5 py-0.5 rounded text-[10px]">
              Ctrl K
            </kbd>
          </button>

          {/* System Telemetry Pill */}
          <div className="hidden md:flex items-center gap-2 px-3 py-1 bg-emerald-950/40 border border-emerald-800/40 rounded-full text-xs font-mono text-emerald-400">
            <Activity className="w-3.5 h-3.5 animate-pulse" />
            <span>SYSTEM ONLINE</span>
          </div>

          {/* User Profile & Logout */}
          <div className="flex items-center gap-3 border-l border-slate-800 pl-4">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 font-semibold text-xs">
                {user?.full_name ? user.full_name.charAt(0) : user?.email?.charAt(0) || 'A'}
              </div>
              <div className="hidden lg:block text-left">
                <p className="text-xs font-medium text-slate-200">{user?.full_name || user?.email || 'SOC Analyst'}</p>
                <p className="text-[10px] font-mono text-emerald-400 uppercase">{user?.role || 'ANALYST'}</p>
              </div>
            </div>

            <button
              onClick={logout}
              title="Logout"
              className="p-2 text-slate-400 hover:text-red-400 hover:bg-slate-800 rounded-lg transition"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      <GlobalSearchModal isOpen={isSearchOpen} onClose={() => setIsSearchOpen(false)} />
    </>
  );
};
