export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AlertStatus = 'NEW' | 'IN_PROGRESS' | 'TRIAGED' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface Alert {
  id: string;
  title: string;
  description?: string;
  source: string;
  event_type: string;
  severity: AlertSeverity;
  status: AlertStatus;
  risk_score: number;
  host?: string;
  ip?: string;
  user?: string;
  command_line?: string;
  file_hash?: string;
  incident_id?: string;
  assigned_user_id?: string;
  created_at: string;
  updated_at?: string;
}

export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentPriority = 'P1_CRITICAL' | 'P2_HIGH' | 'P3_MEDIUM' | 'P4_LOW';
export type IncidentStatus = 'OPEN' | 'TRIAGED' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
export type IncidentCategory = 'MALWARE' | 'PHISHING' | 'RANSOMWARE' | 'EXFILTRATION' | 'UNAUTHORIZED_ACCESS' | 'SUSPICIOUS_BEHAVIOR';

export interface Incident {
  id: string;
  incident_code: string;
  title: string;
  description?: string;
  severity: IncidentSeverity;
  priority: IncidentPriority;
  status: IncidentStatus;
  category: IncidentCategory;
  risk_score: number;
  assigned_to_user_id?: string;
  created_by_user_id?: string;
  related_alerts_count?: number;
  created_at: string;
  updated_at?: string;
}

export type InvestigationStatus = 'DRAFT' | 'ACTIVE' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED';

export interface Investigation {
  id: string;
  investigation_code: string;
  title: string;
  description?: string;
  incident_id?: string;
  status: InvestigationStatus;
  created_at: string;
  updated_at?: string;
}

export type IOCType = 'IP' | 'DOMAIN' | 'URL' | 'FILE_HASH_MD5' | 'FILE_HASH_SHA256' | 'EMAIL' | 'JA3_FINGERPRINT';
export type ThreatReputationLevel = 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';

export interface IOC {
  id: string;
  indicator_value: string;
  ioc_type: IOCType;
  reputation_level: ThreatReputationLevel;
  risk_score: number;
  confidence_score: number;
  threat_category?: string;
  sources?: string[];
  first_seen?: string;
  last_seen?: string;
  created_at: string;
}

export type RuleType = 'SIGMA' | 'YARA' | 'SURICATA' | 'CUSTOM';
export type RuleStatus = 'DRAFT' | 'EXPERIMENTAL' | 'CANDIDATE' | 'TESTING' | 'ACTIVE' | 'DEPRECATED' | 'DISABLED';

export interface DetectionRule {
  id: string;
  rule_code: string;
  name: string;
  description?: string;
  rule_type: RuleType;
  status: RuleStatus;
  severity: string;
  category?: string;
  version: string;
  raw_content: string;
  quality_score: number;
  is_active: boolean;
  created_at: string;
}

export type CaseStatus = 'OPEN' | 'IN_PROGRESS' | 'PENDING_APPROVAL' | 'RESOLVED' | 'CLOSED';
export type CaseSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type CasePriority = 'P1' | 'P2' | 'P3' | 'P4';
export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'AUTO_APPROVED' | 'REJECTED' | 'CANCELLED';

export interface CaseApproval {
  id: string;
  case_id: string;
  title: string;
  description?: string;
  status: ApprovalStatus;
  is_auto_approval: boolean;
  approver_id?: string;
  decision_notes?: string;
  created_at: string;
  decided_at?: string;
}

export interface PlatformMetrics {
  total_alerts: number;
  alerts_today: number;
  critical_alerts: number;
  open_incidents: number;
  active_investigations: number;
  open_cases: number;
  pending_approvals: number;
  active_playbook_executions: number;
  total_iocs: number;
  malicious_iocs: number;
  total_detection_rules: number;
  active_ai_agents: number;
}

export interface SOCMetrics {
  mttd_seconds?: number;
  mttr_seconds?: number;
  avg_triage_time_seconds: number;
  avg_investigation_duration_seconds: number;
  avg_approval_wait_seconds?: number;
  alert_to_incident_ratio: number;
  incident_to_case_ratio: number;
  conversion_funnel: Record<string, number>;
}

export interface AlertMetrics {
  total_count: number;
  severity_breakdown: Record<string, number>;
  status_breakdown: Record<string, number>;
  false_positive_rate: number;
  top_sources: Record<string, any>[];
}

export interface IncidentMetrics {
  total_created: number;
  open_count: number;
  resolved_count: number;
  severity_distribution: Record<string, number>;
  priority_distribution: Record<string, number>;
  avg_resolution_seconds?: number;
  sla_breaches: number;
}

export interface StagePerformanceMetric {
  stage: string;
  execution_count: number;
  avg_duration_ms: number;
  failure_rate: number;
  retry_count: number;
  is_bottleneck: boolean;
}

export interface PipelineMetrics {
  total_executions: number;
  successful_executions: number;
  failed_executions: number;
  cancelled_executions: number;
  avg_duration_seconds?: number;
  median_duration_seconds?: number;
  recovery_frequency: number;
  stage_performance: StagePerformanceMetric[];
  bottleneck_stage?: string;
}

export interface SingleAgentMetric {
  agent_name: string;
  execution_count: number;
  successful_executions: number;
  failed_executions: number;
  success_rate: number;
  avg_execution_duration_ms: number;
  avg_confidence_score: number;
  total_findings_generated: number;
  total_recommendations_generated: number;
}

export interface AgentMetrics {
  total_agent_runs: number;
  overall_success_rate: number;
  avg_overall_confidence: number;
  consensus_score: number;
  agents: SingleAgentMetric[];
}

export interface ThreatIntelMetrics {
  total_iocs: number;
  malicious_count: number;
  suspicious_count: number;
  benign_count: number;
  unknown_count: number;
  type_breakdown: Record<string, number>;
}

export interface DetectionMetrics {
  total_rules: number;
  active_production_rules: number;
  candidate_rules: number;
  experimental_rules: number;
  rule_format_breakdown: Record<string, number>;
  avg_quality_score: number;
  ai_generated_rules_count: number;
}

export interface CaseMetrics {
  total_cases: number;
  open_cases: number;
  resolved_cases: number;
  sla_breaches: number;
  pending_approvals: number;
  avg_resolution_hours?: number;
  approval_velocity_hours?: number;
}

export interface PlaybookMetrics {
  total_executions: number;
  successful_executions: number;
  failed_executions: number;
  is_safe_simulated_mode: boolean;
  playbook_usage_count: Record<string, number>;
}

export interface ComponentHealthStatus {
  service_name: string;
  status: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY';
  latency_ms: number;
  message?: string;
}

export interface SystemHealthMetrics {
  overall_status: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY';
  components: ComponentHealthStatus[];
  active_connections: number;
}

export interface ObservabilityOverview {
  time_window: string;
  platform: PlatformMetrics;
  soc: SOCMetrics;
  alerts: AlertMetrics;
  incidents: IncidentMetrics;
  pipeline: PipelineMetrics;
  agents: AgentMetrics;
  threat_intel: ThreatIntelMetrics;
  detections: DetectionMetrics;
  cases: CaseMetrics;
  playbooks: PlaybookMetrics;
  health: SystemHealthMetrics;
}


export interface Case {
  id: string;
  case_number: string;
  title: string;
  description?: string;
  status: CaseStatus;
  severity: CaseSeverity;
  priority: CasePriority;
  owner_id?: string;
  sla_breached: boolean;
  opened_at: string;
  closed_at?: string;
  created_at: string;
}

export type PlaybookStatus = 'DRAFT' | 'ACTIVE' | 'DISABLED' | 'ARCHIVED';
export type ExecutionStatus = 'PENDING' | 'RUNNING' | 'WAITING_APPROVAL' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export interface Playbook {
  id: string;
  name: string;
  description?: string;
  status: PlaybookStatus;
  category: string;
  trigger_type: string;
  is_active: boolean;
  created_at: string;
}

export interface PlaybookExecution {
  id: string;
  playbook_id: string;
  incident_id?: string;
  status: ExecutionStatus;
  current_step_index: number;
  started_at: string;
  completed_at?: string;
}

export type PipelineStage =
  | 'TRIAGING'
  | 'CORRELATING'
  | 'INVESTIGATION_STARTED'
  | 'THREAT_HUNTING'
  | 'DFIR_ANALYSIS'
  | 'THREAT_INTELLIGENCE'
  | 'DETECTION_GENERATION'
  | 'INCIDENT_SYNTHESIS'
  | 'AWAITING_REVIEW'
  | 'RESPONSE_APPROVED'
  | 'RESPONSE_EXECUTING'
  | 'RESPONSE_COMPLETED'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

export type PipelineStatus =
  | 'IDLE'
  | 'RUNNING'
  | 'PAUSED'
  | 'AWAITING_APPROVAL'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

export interface StageResult {
  stage: PipelineStage;
  status: 'SUCCESS' | 'FAILURE' | 'SKIPPED' | 'PENDING';
  executed_by?: string;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  result_data?: Record<string, any>;
  error_message?: string;
  retry_count: number;
}

export interface PipelineContext {
  pipeline_id: string;
  investigation_id: string;
  incident_id?: string;
  status: PipelineStatus;
  current_stage: PipelineStage;
  stage_results: Record<string, StageResult>;
  approval_status: string;
  approval_id?: string;
  auto_approve_routine: boolean;
  created_at: string;
  updated_at: string;
}

export interface PipelineTimelineEntry {
  id: string;
  stage: PipelineStage;
  timestamp: string;
  status: string;
  message: string;
  details?: Record<string, any>;
}

export interface AgentInfo {
  name: string;
  status: 'IDLE' | 'RUNNING' | 'SUCCESS' | 'FAILURE' | 'WAITING';
  capabilities: string[];
  last_execution?: string;
  current_investigation_id?: string;
  confidence?: number;
  findings_summary?: string;
}

export interface SOCOverviewMetrics {
  total_alerts: number;
  critical_alerts: number;
  open_incidents: number;
  critical_incidents: number;
  active_investigations: number;
  pending_approvals: number;
  total_iocs: number;
  malicious_iocs: number;
  total_detection_rules: number;
  active_playbooks: number;
  average_risk_score: number;
  system_status: string;
}

export interface SystemHealthData {
  database: string;
  redis: string;
  elasticsearch: string;
}

export interface User {
  id: string;
  email: string;
  full_name?: string;
  role: string;
}

export interface PaginatedMeta {
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  meta: PaginatedMeta;
}

export interface DemoScenario {
  scenario_id: string;
  name: string;
  description: string;
  attack_phases: string[];
  synthetic_alerts: any[];
  expected_agents: string[];
  expected_mitre_techniques: string[];
  expected_risk_range: number[];
  expected_severity: string;
  expected_governance_state: string;
  expected_final_stage: string;
}

export interface DemoRunRequest {
  auto_approve?: boolean;
  inject_stage_failure?: string;
}

export interface DemoAssertion {
  assertion_id: number;
  name: string;
  passed: boolean;
  details: string;
}

export interface DemoMetrics {
  execution_duration_ms: number;
  pipeline_duration_ms: number;
  agent_latencies_ms: Record<string, number>;
  db_operations_count: number;
}

export interface DemoExecutionResult {
  scenario_id: string;
  name: string;
  status: string;
  duration_ms: number;
  created_alert_ids: string[];
  created_incident_id?: string;
  created_investigation_id?: string;
  created_case_id?: string;
  approval_status: string;
  soar_execution_mode: string;
  pipeline_final_stage: string;
  assertions_passed: number;
  total_assertions: number;
  assertions: DemoAssertion[];
  agent_findings: Record<string, any>;
  mitre_techniques: string[];
  risk_score: number;
  severity: string;
  generated_rules: any[];
  response_plan: any[];
  metrics: DemoMetrics;
}

export interface DemoReport {
  scenario_id: string;
  scenario_name: string;
  generated_at: string;
  overview: string;
  attack_chain: any[];
  observed_telemetry: any[];
  ai_agent_findings: Record<string, any>;
  mitre_mappings: string[];
  threat_intelligence: Record<string, any>;
  detection_rules: any[];
  risk_assessment: Record<string, any>;
  incident_commander_synthesis: Record<string, any>;
  evidence_gaps: string[];
  response_plan: Record<string, any>;
  approval_decision: Record<string, any>;
  soar_execution_result: Record<string, any>;
  timeline_summary: any[];
  final_outcome: string;
}


export interface APIResponse<T> {
  message: string;
  data: T;
}
