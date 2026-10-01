import { apiClient } from './client';
import {
  APIResponse,
  PaginatedResponse,
  SOCOverviewMetrics,
  Alert,
  Incident,
  Investigation,
  IOC,
  DetectionRule,
  Case,
  CaseApproval,
  Playbook,
  PlaybookExecution,
  PipelineContext,
  PipelineTimelineEntry,
  SystemHealthData,
  User,
  ObservabilityOverview,
  AlertMetrics,
  IncidentMetrics,
  PipelineMetrics,
  AgentMetrics,
  ThreatIntelMetrics,
  DetectionMetrics,
  CaseMetrics,
  PlaybookMetrics,
  SystemHealthMetrics,
} from '../types';


export const authApi = {
  login: async (identifier: string, password: string) => {
    const formData = new URLSearchParams();
    formData.append('username', identifier);
    formData.append('password', password);
    const res = await apiClient.post<any>('/auth/login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    const tokenData = res.data?.data || res.data;
    return tokenData as { access_token: string; token_type: string; expires_in_seconds?: number };
  },
  getMe: async () => {
    const res = await apiClient.get<APIResponse<User>>('/auth/me');
    return res.data.data;
  },
};

export const overviewApi = {
  getOverviewMetrics: async () => {
    const res = await apiClient.get<APIResponse<SOCOverviewMetrics>>('/overview');
    return res.data.data;
  },
};

export const alertsApi = {
  listAlerts: async (params?: Record<string, any>) => {
    const res = await apiClient.get<PaginatedResponse<Alert>>('/alerts', { params });
    return res.data;
  },
  getAlertDetail: async (id: string) => {
    const res = await apiClient.get<APIResponse<Alert>>(`/alerts/${id}`);
    return res.data.data;
  },
  updateAlertStatus: async (id: string, status: string) => {
    const res = await apiClient.patch<APIResponse<Alert>>(`/alerts/${id}/status`, { status });
    return res.data.data;
  },
};

export const incidentsApi = {
  listIncidents: async (params?: Record<string, any>) => {
    const res = await apiClient.get<PaginatedResponse<Incident>>('/incidents', { params });
    return res.data;
  },
  getIncidentDetail: async (id: string) => {
    const res = await apiClient.get<APIResponse<Incident>>(`/incidents/${id}`);
    return res.data.data;
  },
  closeIncident: async (id: string, closureNotes: string) => {
    const res = await apiClient.post<APIResponse<Incident>>(`/incidents/${id}/close`, { closure_notes: closureNotes });
    return res.data.data;
  },
};

export const investigationsApi = {
  listInvestigations: async (params?: Record<string, any>) => {
    const res = await apiClient.get<PaginatedResponse<Investigation>>('/investigations', { params });
    return res.data;
  },
  getInvestigationDetail: async (id: string) => {
    const res = await apiClient.get<APIResponse<Investigation>>(`/investigations/${id}`);
    return res.data.data;
  },
};

export const aiApi = {
  getAgentHealth: async () => {
    const res = await apiClient.get<APIResponse<any>>('/ai/health');
    return res.data.data;
  },
  getAgentsSummary: async () => {
    const res = await apiClient.get<APIResponse<any>>('/ai/agents');
    return res.data.data;
  },
};

export const pipelineApi = {
  runPipeline: async (investigationId: string, payload?: { initial_alerts?: any[]; auto_approve_routine?: boolean }) => {
    const res = await apiClient.post<APIResponse<PipelineContext>>(`/ai/investigations/${investigationId}/run`, payload || {});
    return res.data.data;
  },
  getPipelineStatus: async (investigationId: string) => {
    const res = await apiClient.get<APIResponse<PipelineContext>>(`/ai/investigations/${investigationId}/status`);
    return res.data.data;
  },
  getPipelineTimeline: async (investigationId: string) => {
    const res = await apiClient.get<APIResponse<PipelineTimelineEntry[]>>(`/ai/investigations/${investigationId}/timeline`);
    return res.data.data;
  },
  cancelPipeline: async (investigationId: string) => {
    const res = await apiClient.post<APIResponse<PipelineContext>>(`/ai/investigations/${investigationId}/cancel`);
    return res.data.data;
  },
};

export const threatIntelApi = {
  listIOCs: async (params?: Record<string, any>) => {
    const res = await apiClient.get<PaginatedResponse<IOC>>('/threat-intelligence/iocs', { params });
    return res.data;
  },
  getStatistics: async () => {
    const res = await apiClient.get<APIResponse<any>>('/threat-intelligence/statistics');
    return res.data.data;
  },
};

export const mitreApi = {
  getMatrix: async () => {
    const res = await apiClient.get<APIResponse<any>>('/mitre/matrix');
    return res.data.data;
  },
  getCoverage: async () => {
    const res = await apiClient.get<APIResponse<any>>('/mitre/coverage');
    return res.data.data;
  },
};

export const detectionsApi = {
  listRules: async (params?: Record<string, any>) => {
    const res = await apiClient.get<PaginatedResponse<DetectionRule>>('/detection-rules', { params });
    return res.data;
  },
  getRuleDetail: async (id: string) => {
    const res = await apiClient.get<APIResponse<DetectionRule>>(`/detection-rules/${id}`);
    return res.data.data;
  },
};

export const casesApi = {
  listCases: async (params?: Record<string, any>) => {
    const res = await apiClient.get<PaginatedResponse<Case>>('/cases', { params });
    return res.data;
  },
  getCaseDetail: async (id: string) => {
    const res = await apiClient.get<APIResponse<Case>>(`/cases/${id}`);
    return res.data.data;
  },
  listPendingApprovals: async () => {
    const res = await apiClient.get<APIResponse<CaseApproval[]>>('/cases/pending-approvals');
    return res.data.data;
  },
  listCaseApprovals: async (caseId: string) => {
    const res = await apiClient.get<APIResponse<CaseApproval[]>>(`/cases/${caseId}/approvals`);
    return res.data.data;
  },
  processApprovalDecision: async (caseId: string, approvalId: string, approved: boolean, decisionNotes?: string) => {
    const res = await apiClient.post<APIResponse<CaseApproval>>(`/cases/${caseId}/approvals/${approvalId}/decision`, {
      approved,
      decision_notes: decisionNotes || '',
    });
    return res.data.data;
  },
};

export const playbooksApi = {
  listPlaybooks: async (params?: Record<string, any>) => {
    const res = await apiClient.get<PaginatedResponse<Playbook>>('/playbooks', { params });
    return res.data;
  },
  listExecutions: async (params?: Record<string, any>) => {
    const res = await apiClient.get<PaginatedResponse<PlaybookExecution>>('/playbooks/executions', { params });
    return res.data;
  },
};

export const timelineApi = {
  getTimelineEvents: async (params?: Record<string, any>) => {
    const res = await apiClient.get<PaginatedResponse<any>>('/timeline', { params });
    return res.data;
  },
};

export const healthApi = {
  getHealth: async () => {
    const res = await apiClient.get<APIResponse<SystemHealthData>>('/health');
    return res.data.data;
  },
};

export const observabilityApi = {
  getOverview: async (timeWindow: string = '24h') => {
    const res = await apiClient.get<ObservabilityOverview>('/observability/overview', {
      params: { time_window: timeWindow },
    });
    return res.data;
  },
  getAlerts: async (timeWindow: string = '24h') => {
    const res = await apiClient.get<AlertMetrics>('/observability/alerts', {
      params: { time_window: timeWindow },
    });
    return res.data;
  },
  getIncidents: async (timeWindow: string = '24h') => {
    const res = await apiClient.get<IncidentMetrics>('/observability/incidents', {
      params: { time_window: timeWindow },
    });
    return res.data;
  },
  getPipeline: async (timeWindow: string = '24h') => {
    const res = await apiClient.get<PipelineMetrics>('/observability/pipeline', {
      params: { time_window: timeWindow },
    });
    return res.data;
  },
  getAgents: async (timeWindow: string = '24h') => {
    const res = await apiClient.get<AgentMetrics>('/observability/agents', {
      params: { time_window: timeWindow },
    });
    return res.data;
  },
  getThreatIntel: async (timeWindow: string = '24h') => {
    const res = await apiClient.get<ThreatIntelMetrics>('/observability/threat-intelligence', {
      params: { time_window: timeWindow },
    });
    return res.data;
  },
  getDetections: async (timeWindow: string = '24h') => {
    const res = await apiClient.get<DetectionMetrics>('/observability/detections', {
      params: { time_window: timeWindow },
    });
    return res.data;
  },
  getCases: async (timeWindow: string = '24h') => {
    const res = await apiClient.get<CaseMetrics>('/observability/cases', {
      params: { time_window: timeWindow },
    });
    return res.data;
  },
  getPlaybooks: async (timeWindow: string = '24h') => {
    const res = await apiClient.get<PlaybookMetrics>('/observability/playbooks', {
      params: { time_window: timeWindow },
    });
    return res.data;
  },
  getSystemHealth: async () => {
    const res = await apiClient.get<SystemHealthMetrics>('/observability/system');
    return res.data;
  },
  getPrometheusMetrics: async () => {
    const res = await apiClient.get<string>('/observability/metrics');
    return res.data;
  },
};

export const demoApi = {
  listScenarios: async (): Promise<any[]> => {
    const res = await apiClient.get('/demo/scenarios');
    return res.data;
  },
  getScenario: async (scenarioId: string): Promise<any> => {
    const res = await apiClient.get(`/demo/scenarios/${scenarioId}`);
    return res.data;
  },
  runScenario: async (scenarioId: string, req: { auto_approve?: boolean } = {}): Promise<any> => {
    const res = await apiClient.post(`/demo/scenarios/${scenarioId}/run`, req);
    return res.data;
  },
  getScenarioResult: async (scenarioId: string): Promise<any> => {
    const res = await apiClient.get(`/demo/scenarios/${scenarioId}/result`);
    return res.data;
  },
  getScenarioReport: async (scenarioId: string): Promise<any> => {
    const res = await apiClient.get(`/demo/scenarios/${scenarioId}/report`);
    return res.data;
  },
  cleanupScenario: async (scenarioId: string): Promise<any> => {
    const res = await apiClient.delete(`/demo/scenarios/${scenarioId}`);
    return res.data;
  },
};


