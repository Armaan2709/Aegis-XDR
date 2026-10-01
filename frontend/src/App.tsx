import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from './context/AuthContext';
import { SOCLayout } from './components/layout/SOCLayout';
import { Dashboard } from './pages/Dashboard';
import { Alerts } from './pages/Alerts';
import { Incidents } from './pages/Incidents';
import { Investigations } from './pages/Investigations';
import { Agents } from './pages/Agents';
import { ThreatIntel } from './pages/ThreatIntel';
import { Mitre } from './pages/Mitre';
import { Detections } from './pages/Detections';
import { Cases } from './pages/Cases';
import { Approvals } from './pages/Approvals';
import { Playbooks } from './pages/Playbooks';
import { Timeline } from './pages/Timeline';
import { SystemHealth } from './pages/SystemHealth';
import { Analytics } from './pages/Analytics';
import { DemoScenarios } from './pages/DemoScenarios';
import { Login } from './pages/Login';
import { LoadingSpinner } from './components/common/LoadingSpinner';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) return <LoadingSpinner label="Authenticating Analyst Session..." />;
  if (!isAuthenticated) return <Navigate to="/login" replace />;

  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<Login />} />

            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <SOCLayout />
                </ProtectedRoute>
              }
            >
              <Route index element={<Dashboard />} />
              <Route path="demo" element={<DemoScenarios />} />
              <Route path="analytics" element={<Analytics />} />
              <Route path="alerts" element={<Alerts />} />
              <Route path="incidents" element={<Incidents />} />
              <Route path="investigations" element={<Investigations />} />
              <Route path="agents" element={<Agents />} />
              <Route path="threat-intelligence" element={<ThreatIntel />} />
              <Route path="mitre" element={<Mitre />} />
              <Route path="detections" element={<Detections />} />
              <Route path="cases" element={<Cases />} />
              <Route path="approvals" element={<Approvals />} />
              <Route path="playbooks" element={<Playbooks />} />
              <Route path="timeline" element={<Timeline />} />
              <Route path="system-health" element={<SystemHealth />} />
            </Route>


            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
};

export default App;
