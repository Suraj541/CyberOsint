/**
 * TypeScript Data Models for Cybersecurity OSINT Platform
 * Conforms to IMPLEMENT.md Section 20, 21, 22.
 */

export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface ExtractedEntity {
  id?: number;
  entity_type: string;
  name: string;
  normalized_name?: string;
  confidence?: number;
  context_snippet?: string;
}

export interface VideoTimestampItem {
  timestamp_str: string;
  seconds: number;
  topic: string;
  text?: string;
  entities?: string[];
}

export interface VideoMetadata {
  channel?: string;
  duration?: number;
  duration_formatted?: string;
  thumbnail_url?: string;
  conference?: string;
  speakers?: string[];
  language?: string;
  timestamps?: VideoTimestampItem[];
  has_transcript?: boolean;
}

export interface DocumentChunkItem {
  chunk_index: number;
  heading: string;
  text: string;
  char_start?: number;
  char_end?: number;
  page_number?: number;
}

export interface DocumentMetadata {
  document_type: "pdf" | "html" | "markdown" | "txt" | "docx" | "pptx" | "unknown";
  authors?: string[];
  publication_date?: string;
  abstract?: string;
  page_count?: number;
  word_count?: number;
  file_size_bytes?: number;
  section_headings?: string[];
  copyright_notice?: string;
  retention_mode?: "full_text" | "metadata_only" | "fair_use_summary";
  chunks_count?: number;
  chunks_preview?: DocumentChunkItem[];
}

export interface ContentItem {
  id: number;
  title: string;
  description?: string;
  summary?: string;
  canonical_url: string;
  content_type?: "article" | "cve" | "advisory" | "tool" | "video" | "paper" | "report" | "document" | (string & {});
  source: string;
  category?: string;
  author?: string;
  published_at?: string;
  discovered_at?: string;
  tags?: string[];
  entities?: ExtractedEntity[];
  raw_body?: string;
  severity?: SeverityLevel;
  cvss_score?: number;
  video_metadata?: VideoMetadata;
  document_metadata?: DocumentMetadata;
  source_quality?: SourceQuality;
  ai_summary?: ContentSummary;
}

export interface VulnerabilityItem {
  cve_id: string;
  cvss_score?: number;
  severity: SeverityLevel;
  description: string;
  cwe_id?: string;
  affected_products?: string[];
  vendor?: string;
  published_at: string;
  is_exploited?: boolean;
  references?: string[];
}

export interface ThreatIntelligenceItem {
  id: string;
  title: string;
  threat_actor?: string;
  target_sectors?: string[];
  malware_families?: string[];
  mitre_techniques?: string[];
  summary: string;
  confidence: number;
  source: string;
  published_at: string;
}

export interface SourceConnectorItem {
  id: number;
  name: string;
  connector_type: "rss" | "cve" | "github" | "cert" | "custom";
  url: string;
  is_active: boolean;
  fetch_interval_minutes: number;
  last_fetched_at?: string;
  last_status?: "success" | "error" | "pending";
  items_count?: number;
  quality?: SourceQuality;
}

export interface DashboardMetrics {
  total_content: number;
  active_sources: number;
  tracked_cves: number;
  threat_advisories: number;
  total_entities?: number;
  system_health: "healthy" | "degraded" | "offline" | "standby";
  last_updated: string;
}

export interface TrendingTopic {
  name: string;
  entity_type: string;
  mention_count: number;
  confidence: number;
}

export interface DashboardData {
  metrics: DashboardMetrics;
  latest_news: ContentItem[];
  critical_vulnerabilities: ContentItem[];
  new_research: ContentItem[];
  trending_topics: TrendingTopic[];
  new_tools: ContentItem[];
  latest_videos: ContentItem[];
  threat_intelligence: ContentItem[];
}

export interface SearchFacetItem {
  key: string;
  count: number;
}

export interface SearchHitItem {
  id: number;
  title: string;
  canonical_url: string;
  content_type: string;
  category?: string;
  source?: string;
  published_at?: string;
  score: number;
  highlight?: string;
  entities?: string[];
  tags?: string[];
  rrf_score?: number;
  matched_chunk?: string;
  keyword_rank?: number;
  semantic_rank?: number;
  keyword_score?: number;
  semantic_score?: number;
}

export interface SearchResponse {
  total: number;
  page: number;
  page_size: number;
  hits: SearchHitItem[];
  facets?: Record<string, SearchFacetItem[]>;
  took_ms: number;
  engine?: string;
  text_count?: number;
  vector_count?: number;
  text_status?: string;
  vector_status?: string;
  engine_status?: string;
  error?: string;
}


export interface RelatedEntityItem {
  id: number;
  name: string;
  entity_type: string;
  normalized_name?: string;
  mention_count?: number;
  description?: string;
}

export interface TimelineEvent {
  date?: string;
  title: string;
  event_type: string;
  content_id?: number;
  url?: string;
}

export interface CVESeverityDetail {
  cvss_score?: number;
  severity_rating?: SeverityLevel | string;
  vector_string?: string;
  cwe_id?: string;
}

export interface EntityDetail {
  id: number;
  name: string;
  entity_type: string;
  normalized_name: string;
  description?: string;
  metadata_json?: string;
  parsed_metadata?: Record<string, any>;
  content_count: number;
  created_at: string;
  updated_at: string;

  // Correlated content
  articles?: ContentItem[];
  reports?: ContentItem[];
  linked_content?: Array<{
    content_id: number;
    title: string;
    canonical_url: string;
    content_type: string;
    confidence?: number;
    extraction_method?: string;
    context_snippet?: string;
    published_at?: string;
  }>;

  // Relationships & Activity
  related_entities?: RelatedEntityItem[];
  timeline?: TimelineEvent[];

  // CVE specific (IMPLEMENT.md Section 23)
  severity?: CVESeverityDetail;
  affected_products?: string[];
  references?: string[];

  // Malware specific (IMPLEMENT.md Section 23)
  aliases?: string[];
  threat_actors?: RelatedEntityItem[];
  campaigns?: string[];
  techniques?: RelatedEntityItem[];
  tools?: RelatedEntityItem[];
}

// --------------------------------------------------------------------------
// MITRE ATT&CK Interfaces (IMPLEMENT.md Section 26)
// --------------------------------------------------------------------------

export interface AttackTactic {
  id: string;
  name: string;
  description: string;
  order: number;
  url?: string;
}

export interface AttackTechnique {
  id: string;
  name: string;
  description: string;
  tactic_id: string;
  tactic_name?: string;
  parent_technique_id?: string;
  is_subtechnique: boolean;
  platforms: string[];
  data_sources: string[];
  detection_methods?: string;
  url?: string;
}

export interface AttackGroup {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  associated_techniques: string[];
  associated_software: string[];
  url?: string;
}

export interface AttackSoftware {
  id: string;
  name: string;
  software_type: string;
  aliases: string[];
  description: string;
  associated_techniques: string[];
  url?: string;
}

export interface AttackMitigation {
  id: string;
  name: string;
  description: string;
  associated_techniques: string[];
  url?: string;
}

export interface AttackDataSource {
  id: string;
  name: string;
  description: string;
  collection_layers: string[];
  associated_techniques: string[];
  url?: string;
}

export interface AttackRelationship {
  source_id: string;
  source_type: string;
  relationship: "uses" | "implements" | "belongs_to" | "detected_by" | "mitigates" | string;
  target_id: string;
  target_type: string;
  description?: string;
  confidence: number;
}

export interface AttackTechniqueDetail {
  technique: AttackTechnique;
  tactic?: AttackTactic;
  subtechniques: AttackTechnique[];
  threat_actors: AttackGroup[];
  software: AttackSoftware[];
  mitigations: AttackMitigation[];
  data_sources: AttackDataSource[];
}

export interface AttackMatrixColumn {
  tactic: AttackTactic;
  techniques_count: number;
  total_techniques_count: number;
  techniques: Array<{
    technique: AttackTechnique;
    subtechniques: AttackTechnique[];
  }>;
}

export interface AttackMatrixResponse {
  matrix: AttackMatrixColumn[];
  total_tactics: number;
  total_techniques: number;
}

// --------------------------------------------------------------------------
// Knowledge Graph Interfaces (IMPLEMENT.md Section 27)
// --------------------------------------------------------------------------

export interface GraphNode {
  id: number;
  name: string;
  entity_type: string;
  normalized_name: string;
  degree: number;
  metadata?: Record<string, any>;
}

export interface GraphEdge {
  id: number;
  source_id: number;
  target_id: number;
  relationship: string;
  confidence: number;
  source_content_id?: number;
  source_content_title?: string;
}

export interface GraphSubgraph {
  center_id: number;
  depth: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphPath {
  source_id: number;
  target_id: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  length: number;
}

export interface GraphStats {
  total_nodes: number;
  total_edges: number;
  relationship_types: Record<string, number>;
  entity_types: Record<string, number>;
  top_hubs: Array<{
    id: number;
    name: string;
    entity_type: string;
    degree: number;
  }>;
}

export interface RelationshipItem {
  id: number;
  source_entity_id: number;
  relationship: string;
  target_entity_id: number;
  confidence: number;
  source_content_id?: number;
  created_at: string;
}

export interface RelationshipCreateInput {
  source_entity_id: number;
  relationship: string;
  target_entity_id: number;
  confidence?: number;
  source_content_id?: number;
}

// --------------------------------------------------------------------------
// Source Reliability Interfaces (IMPLEMENT.md Section 28)
// --------------------------------------------------------------------------

export interface SourceQuality {
  source_id: number;
  source_name: string;
  authority: number;
  accuracy: number;
  technical_depth: number;
  originality: number;
  historical_reliability: number;
  overall_score: number;
  quality_tier: string;
  indicator_symbol: string;
  eval_metadata?: Record<string, any>;
  disclaimer: string;
}

// --------------------------------------------------------------------------
// AI Summarization Interfaces (IMPLEMENT.md Section 29)
// --------------------------------------------------------------------------

export interface ContentSummary {
  id: number;
  content_id: number;
  executive_summary: string;
  reported_facts: string[];
  inferences: string[];
  uncertainties: string[];
  key_takeaways: string[];
  source_attribution?: string;
  model: string;
  model_version: string;
  prompt_version: string;
  generated_at: string;
  confidence: number;
  validation_status: "passed" | "flagged" | "rejected" | string;
  validation_score: number;
  validation_notes?: Record<string, any>;
}

// --------------------------------------------------------------------------
// AI Research Interfaces (IMPLEMENT.md Section 30)
// --------------------------------------------------------------------------

export interface ResearchEvidenceItem {
  citation_id: number;
  content_id: number;
  title: string;
  source_name: string;
  canonical_url: string;
  published_at?: string;
  quality_tier: string;
  quality_score: number;
  relevance_score: number;
  snippet: string;
  matched_entities: string[];
}

export interface ResearchSynthesis {
  executive_answer: string;
  key_findings: string[];
  threat_activity: string[];
  vulnerabilities: string[];
  mitigations: string[];
  evidence_gaps: string[];
  confidence: number;
}

export interface PipelineStageTelemetry {
  stage_number: number;
  stage_name: string;
  status: string;
  details?: string;
  item_count: number;
}

export interface QueryExpansionInfo {
  original_query: string;
  expanded_terms: string[];
  detected_entities: string[];
  search_keywords: string;
}

export interface ResearchResponse {
  question: string;
  expansion: QueryExpansionInfo;
  pipeline_stages: PipelineStageTelemetry[];
  evidence: ResearchEvidenceItem[];
  synthesis: ResearchSynthesis;
  execution_time_ms: number;
}

export interface SuggestedResearchQuery {
  id: string;
  title: string;
  question: string;
  category: string;
  suggested_entities: string[];
}

// Section 31 (Step 30): Personalized Recommendations Interfaces
export interface RecommendationItem {
  content_id: number;
  title: string;
  description?: string;
  summary?: string;
  canonical_url: string;
  content_type: string;
  category?: string;
  difficulty_level: "beginner" | "intermediate" | "advanced" | "expert" | string;
  score: number;
  match_reasons: string[];
  source: string;
  author?: string;
  published_at?: string;
  tags?: string[];
  entities?: string[];
  is_saved: boolean;
  source_quality_tier?: string;
  source_quality_score?: number;
}

export interface TopicRecommendation {
  topic: string;
  score: number;
  reason: string;
  related_from?: string;
}

export interface UserProfile {
  session_id: string;
  user_id?: number;
  interests: string[];
  difficulty_level: string;
  preferred_types: string[];
  saved_count: number;
  viewed_count: number;
  search_count: number;
}

export interface RecommendationsResponse {
  items: RecommendationItem[];
  suggested_topics: TopicRecommendation[];
  profile_summary: UserProfile;
  total_matched: number;
}

// Section 32 (Step 31): Watchlist Interfaces
export type WatchlistItemType =
  | "cve"
  | "product"
  | "vendor"
  | "threat_actor"
  | "malware"
  | "technology"
  | "topic"
  | "researcher"
  | "tool"
  | "keyword";

export interface WatchlistItem {
  id: number;
  watchlist_id: number;
  item_type: WatchlistItemType;
  item_value: string;
  severity_threshold?: string;
  notify_on_match: boolean;
  created_at?: string;
}

export interface Watchlist {
  id: number;
  session_id: string;
  user_id?: number;
  name: string;
  description?: string;
  is_active: boolean;
  notification_channel: string;
  item_count: number;
  items: WatchlistItem[];
  created_at?: string;
  updated_at?: string;
}

export interface MatchedWatchlistItemHit {
  watchlist_id: number;
  watchlist_name: string;
  item_id: number;
  item_type: string;
  item_value: string;
  matched_field: string;
  matched_text: string;
}

export interface MatchedContentItem {
  content_id: number;
  title: string;
  description?: string;
  summary?: string;
  canonical_url: string;
  content_type: string;
  source: string;
  published_at?: string;
  severity?: SeverityLevel | string;
  cvss_score?: number;
  matched_items: MatchedWatchlistItemHit[];
  match_score: number;
}

export interface WatchlistFeedResponse {
  watchlist_id: number;
  watchlist_name: string;
  total_matches: number;
  items: MatchedContentItem[];
}

// Section 33 (Step 32): Notification & Alerting Interfaces
export type NotificationChannel = "web" | "email" | "push" | "webhook";
export type NotificationImportanceLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type NotificationStatus = "pending" | "sent" | "delivered" | "failed" | "suppressed";

export interface NotificationItem {
  id: number;
  session_id: string;
  user_id?: number;
  watchlist_id?: number;
  watchlist_name?: string;
  content_id?: number;
  content_title?: string;
  content_url?: string;
  title: string;
  body: string;
  summary?: string;
  importance_score: number;
  importance_level: NotificationImportanceLevel;
  channel: NotificationChannel;
  status: NotificationStatus;
  is_read: boolean;
  read_at?: string;
  metadata?: Record<string, any>;
  created_at?: string;
  updated_at?: string;
}

export interface NotificationChannelConfig {
  id?: number;
  session_id: string;
  channel_type: NotificationChannel;
  destination?: string;
  is_enabled: boolean;
  min_importance_threshold: number;
  secret_token?: string;
  description?: string;
  created_at?: string;
  updated_at?: string;
}

export interface NotificationSummary {
  total_count: number;
  unread_count: number;
  critical_count: number;
  high_count: number;
  by_channel: Record<string, number>;
  by_level: Record<string, number>;
  by_status: Record<string, number>;
}

export interface NotificationPipelineRunResult {
  content_id?: number;
  content_title: string;
  matched_watchlists_count: number;
  matched_items_count: number;
  matched_watchlists: any[];
  importance: {
    score: number;
    level: string;
    factors: Record<string, number>;
    exceeds_threshold: boolean;
    threshold_used: number;
    reason: string;
  };
  notifications_created: NotificationItem[];
  dispatch_results: any[];
  status: string;
}

// Section 34 Step 33: Advanced OSINT Connectors
export interface AdvancedConnectorItem {
  id: string;
  priority: number;
  name: string;
  category: string;
  description: string;
  connector_class: string;
  is_enabled: boolean;
  interval_minutes?: number;
  priority_label?: string;
  url?: string;
  api_key_env?: string;
  last_run?: string;
  last_status: "idle" | "success" | "error" | string;
  items_count: number;
}

export interface ConnectorBatchSummaryItem {
  id: string;
  priority: number;
  status: string;
  items_count: number;
  error?: string;
}

export interface ConnectorBatchRunResult {
  total_items_discovered: number;
  executed_connectors: number;
  skipped_connectors: number;
  failed_connectors: number;
  priority_execution_order: string[];
  batch_summary: ConnectorBatchSummaryItem[];
  executed_at: string;
}

export interface ConnectorRunResult {
  id: string;
  status: string;
  items_count: number;
  executed_at: string;
  items: any[];
}

export interface ConnectorHealthSummary {
  total_connectors: number;
  healthy_count: number;
  results: Record<string, any>;
  checked_at: string;
}

// Section 35 Step 34: Declarative Connector Configuration (connectors.yaml)
export interface ConnectorYamlConfigItem {
  key: string;
  enabled: boolean;
  type: string;
  category?: string;
  url?: string;
  interval_minutes: number;
  priority: "critical" | "high" | "medium" | "low" | string;
  description?: string;
  api_key_env?: string;
  auth_token_env?: string;
  timeout: number;
  options?: Record<string, any>;
}

export interface ConnectorsYamlResponse {
  total: number;
  connectors: ConnectorYamlConfigItem[];
  last_loaded_at?: string;
}

export interface RawYamlConfigResponse {
  yaml_content: string;
  last_loaded_at?: string;
}

export interface ConfigReloadResult {
  status: string;
  message: string;
  total_loaded: number;
  synced_to_runtime: number;
  reloaded_at: string;
}

// Section 36 Step 35: Secret Management & Security Auditing
export interface SecretItem {
  key: string;
  configured: boolean;
  masked_value?: string | null;
  description: string;
  required: boolean;
  provider: string;
  last_checked_at: string;
}

export interface SecretScanFinding {
  severity: "critical" | "warning" | "info" | string;
  rule: string;
  file_path: string;
  description: string;
  line_number?: number | null;
}

export interface SecretAuditReport {
  provider: string;
  total_tracked: number;
  configured_count: number;
  missing_required_count: number;
  is_healthy: boolean;
  secrets: SecretItem[];
  gitignore_compliant: boolean;
  findings: SecretScanFinding[];
  verified_patterns: string[];
  audited_at: string;
}

export interface SecretVerifyResult {
  key: string;
  configured: boolean;
  accessible: boolean;
  provider: string;
  masked_preview?: string | null;
  message: string;
}

export interface ManageableSecretItem {
  key: string;
  category: "ai" | "feeds" | "infrastructure" | string;
  configured: boolean;
  masked_value?: string | null;
  description: string;
  required: boolean;
  default_model?: string | null;
  placeholder?: string | null;
}

export interface ManageableSecretsResponse {
  keys: ManageableSecretItem[];
  total: number;
  configured_count: number;
}

export interface SecretSaveResponse {
  status?: string;
  success: boolean;
  saved_keys: string[];
  updated_keys?: string[];
  message: string;
}

export interface SecretTestKeyResponse {
  key?: string;
  success?: boolean;
  connected?: boolean;
  status: "valid" | "invalid" | "untested" | "error" | string;
  message?: string;
  latency_ms?: number | null;
  details?: Record<string, any> | null;
}

// Section 37 Step 36: Security Hardening Controls
export interface HardeningCheckItem {
  id: string;
  name: string;
  category: string;
  status: "hardened" | "active" | "warning" | "disabled" | string;
  description: string;
}

export interface SecurityPostureReport {
  compliance_score: number;
  total_controls: number;
  hardened_controls: number;
  controls: HardeningCheckItem[];
  timestamp: string;
}

export interface SecurityAuditEventItem {
  event_id: string;
  timestamp: string;
  event_type: string;
  actor: string;
  role: string;
  resource: string;
  action: string;
  status: string;
  client_ip: string;
  details: Record<string, any>;
}

export interface URLValidationResult {
  url: string;
  is_safe: boolean;
  hostname: string;
  resolved_ips: string[];
  violation_reason?: string | null;
}

export interface DependencyScanFinding {
  package: string;
  installed_version?: string | null;
  cve: string;
  severity: string;
  description: string;
  recommendation: string;
}

export interface DependencyScanReport {
  status: string;
  total_packages_scanned: number;
  vulnerabilities_found: number;
  scanned_manifests: string[];
  findings: DependencyScanFinding[];
}

export interface SSRFRedirectHop {
  hop_index: number;
  url: string;
  hostname: string;
  status_code: number;
  location_target?: string | null;
  resolved_ips: string[];
  is_safe: boolean;
  violation_reason?: string | null;
}

export interface SSRFRedirectValidationResponse {
  initial_url: string;
  final_url?: string | null;
  is_safe: boolean;
  total_hops: number;
  hops: SSRFRedirectHop[];
  violation_reason?: string | null;
}

// --------------------------------------------------------------------------
// Sandboxed Document Processing Interfaces (Section 39 Step 38)
// --------------------------------------------------------------------------

export interface SandboxPipelineStage {
  stage_name: string;
  status: string;
  duration_ms: number;
  details?: string | null;
}

export interface SandboxSecurityScan {
  is_safe: boolean;
  detected_type: string;
  macros_detected: string[];
  embedded_programs_detected: string[];
  unknown_binaries_detected: string[];
  decompression_ratio: number;
  quarantine_status: string;
  rejection_reason?: string | null;
}

export interface SandboxProcessResponse {
  success: boolean;
  filename: string;
  detected_type: string;
  sanitized_text: string;
  word_count: number;
  char_count: number;
  headings: string[];
  metadata: Record<string, any>;
  security_scan?: SandboxSecurityScan | null;
  stages: SandboxPipelineStage[];
  worker_pid?: number | null;
  execution_time_ms: number;
  error?: string | null;
}

export interface SandboxStatsResponse {
  total_processed: number;
  macros_blocked: number;
  embedded_programs_blocked: number;
  unknown_binaries_blocked: number;
  clean_documents: number;
  quarantined_documents: number;
  threat_neutralization_rate: string;
}

// --------------------------------------------------------------------------
// Section 48 (Step 47): Version 3 Advanced Intelligence Interfaces
// --------------------------------------------------------------------------

export interface ThreatActor {
  id: number;
  name: string;
  aliases: string[];
  country?: string | null;
  motivation?: string | null;
  target_sectors: string[];
  target_countries: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  mitre_group_id?: string | null;
  threat_level: "critical" | "high" | "medium" | "low";
  status: "active" | "dormant" | "disrupted";
  description?: string | null;
  associated_malware: string[];
  associated_cves: string[];
  created_at?: string | null;
  updated_at?: string | null;
}

export interface MalwareFamily {
  id: number;
  name: string;
  aliases: string[];
  malware_type: string;
  target_platforms: string[];
  mitre_software_id?: string | null;
  yara_rules: string[];
  sample_hashes: Array<{ md5?: string; sha1?: string; sha256?: string; type?: string }>;
  severity: "critical" | "high" | "medium" | "low";
  first_seen?: string | null;
  last_seen?: string | null;
  description?: string | null;
  associated_actors: string[];
  associated_cves: string[];
  created_at?: string | null;
}

export interface Campaign {
  id: number;
  name: string;
  actor_name?: string | null;
  status: "active" | "emerging" | "historical";
  start_date?: string | null;
  end_date?: string | null;
  target_sectors: string[];
  target_countries: string[];
  malware_used: string[];
  cves_exploited: string[];
  description?: string | null;
  confidence_score: number;
  created_at?: string | null;
}

export interface TimelineEventItem {
  timestamp: string;
  phase: string;
  title: string;
  description: string;
  source_url?: string | null;
  iocs: string[];
  confidence: number;
}

export interface IncidentTimeline {
  id: number;
  title: string;
  incident_name: string;
  events: TimelineEventItem[];
  summary?: string | null;
  created_at?: string | null;
}

export interface CorrelationCluster {
  id: number;
  title: string;
  matched_entities: Array<{ entity_type: string; value: string }>;
  source_items: Array<{
    source: string;
    title: string;
    url: string;
    timestamp: string;
    snippet?: string | null;
  }>;
  correlation_score: number;
  first_observed: string;
  last_updated: string;
  summary?: string | null;
}

export interface LearningModuleItem {
  id: string;
  title: string;
  description: string;
  duration_hours: number;
  competencies: string[];
  lab_exercise?: string | null;
  linked_content_ids: number[];
}

export interface LearningPath {
  id: number;
  slug: string;
  title: string;
  description: string;
  difficulty: "beginner" | "intermediate" | "advanced";
  estimated_hours: number;
  role: string;
  modules: LearningModuleItem[];
}

export interface ResearchFindingItem {
  topic: string;
  summary: string;
  confidence: number;
  evidence_sources: string[];
}

export interface ResearchAssistantDossier {
  query: string;
  executive_summary: string;
  threat_actor_profile?: Record<string, any> | null;
  key_findings: ResearchFindingItem[];
  attack_path_milestones: string[];
  recommended_mitigations: string[];
  citations: Array<{ source: string; title: string; url: string }>;
  generated_at: string;
}

export interface IntelligenceOverview {
  total_threat_actors: number;
  active_threat_actors: number;
  total_malware_families: number;
  active_campaigns: number;
  incident_timelines_count: number;
  correlated_clusters_count: number;
  learning_paths_count: number;
  top_threat_actors: ThreatActor[];
  recent_campaigns: Campaign[];
}

// =====================================================================
// Section 49 (Step 48): Version 4 Scale Architecture Types
// =====================================================================

export interface WorkerPartitionInfo {
  worker_id: string;
  partition_id: number;
  assigned_sources_count: number;
  status: string;
  current_throughput_eps: number;
  last_heartbeat: string;
}

export interface BackpressureStatus {
  queue_depth: number;
  high_watermark: number;
  low_watermark: number;
  ingestion_rate_multiplier: number;
  is_throttling: boolean;
  active_workers_count: number;
  partitions: WorkerPartitionInfo[];
}

export interface MarketplaceConnector {
  id: number;
  name: string;
  slug: string;
  version: string;
  author: string;
  category: string;
  description?: string | null;
  repository_url?: string | null;
  manifest: Record<string, any>;
  is_installed: boolean;
  is_verified: boolean;
  rating: number;
  downloads_count: number;
  created_at?: string | null;
}

export interface RegionNode {
  id: number;
  region_code: string;
  name: string;
  endpoint: string;
  role: "primary" | "replica" | "edge" | string;
  status: "healthy" | "degraded" | "offline" | string;
  latency_ms: number;
  replication_lag_ms: number;
  active_connections: number;
  last_heartbeat: string;
}

export interface GeoRouteResult {
  routed_region: string;
  endpoint: string;
  estimated_latency_ms: number;
  reason: string;
}

export interface CacheTierStats {
  tier_name: string;
  hits: number;
  misses: number;
  hit_ratio: number;
  item_count: number;
  avg_latency_ms: number;
}

export interface CacheStats {
  overall_hit_ratio: number;
  l1_stats: CacheTierStats;
  l2_stats: CacheTierStats;
  stampede_preventions_count: number;
  active_tags_count: number;
}

export interface ILMPolicy {
  tier: "Hot" | "Warm" | "Cold" | "Frozen" | string;
  retention_days: number;
  shard_count: number;
  replica_count: number;
  compression: string;
  total_docs_indexed: number;
  size_gb: number;
}

export interface FederatedSearchResultItem {
  id: number;
  title: string;
  snippet: string;
  source: string;
  region_origin: string;
  relevance_score: number;
}

export interface FederatedSearchResponse {
  query: string;
  total_hits: number;
  execution_time_ms: number;
  regions_queried: string[];
  results: FederatedSearchResultItem[];
}

export interface CentralityRankingItem {
  node_id: string;
  node_type: string;
  label: string;
  score: number;
  rank: number;
}

export interface CommunityClusterItem {
  cluster_id: number;
  cluster_name: string;
  size: number;
  dominant_actors: string[];
  dominant_cves: string[];
  cohesion_score: number;
}

export interface BlastRadiusResponse {
  target_entity: string;
  max_hops: number;
  total_impacted_nodes: number;
  impact_score: number;
  impacted_technologies: string[];
  impacted_sectors: string[];
  attack_paths: string[][];
}

export interface ModelRouteConfig {
  task_type: string;
  primary_model: string;
  fallback_model: string;
  max_latency_sla_ms: number;
  max_cost_per_query_usd: number;
  circuit_breaker_status: "closed" | "open" | "half_open" | string;
}

export interface ModelRouteResponse {
  task_type: string;
  selected_model: string;
  provider: string;
  routed_reason: string;
  latency_ms: number;
  simulated_result: string;
}

export interface BenchmarkRun {
  id: number;
  suite_name: string;
  dataset_name: string;
  total_samples: number;
  precision_score: number;
  recall_score: number;
  f1_score: number;
  p95_latency_ms: number;
  drift_detected: boolean;
  details: Record<string, any>;
  created_at: string;
}

export interface SourceReputation {
  id: number;
  source_name: string;
  reputation_score: number;
  tier: "gold" | "silver" | "community" | "quarantine" | string;
  corroboration_rate: number;
  false_positive_rate: number;
  latency_rating_ms: number;
  total_items_evaluated: number;
}

export interface ScaleOverview {
  total_workers_active: number;
  ingestion_backpressure_ratio: number;
  marketplace_connectors_count: number;
  installed_connectors_count: number;
  active_regions_count: number;
  cache_hit_ratio: number;
  total_indices_managed: number;
  model_routes_count: number;
  average_benchmark_f1: number;
  gold_tier_sources_count: number;
}

// ── Section 50 & 51 (Step 49): System Readiness & Definition of Done Types ──
export interface DoDCheckItem {
  id: string;
  criterion_number: number;
  category: "Ingestion" | "Normalization" | "Classification" | "Extraction" | "Deduplication" | "Search" | "Intelligence" | "Security" | "Operations" | string;
  title: string;
  description: string;
  passed: boolean;
  evidence: string;
  latency_ms: number;
}

export interface DoDVerificationResponse {
  status: "PASSED" | "WARNING" | "FAILED" | string;
  total_criteria: number;
  passed_criteria: number;
  score_pct: number;
  verified_at: string;
  items: DoDCheckItem[];
}

export interface MilestoneVerificationItem {
  step_number: number;
  code: string;
  name: string;
  category: "Core" | "Pipeline" | "Intelligence" | "Ops" | string;
  implemented: boolean;
  module_path: string;
  test_suite: string;
  status: "VERIFIED" | "PARTIAL" | "PENDING" | string;
}

export interface MilestoneVerificationResponse {
  status: string;
  total_milestones: number;
  completed_milestones: number;
  completion_pct: number;
  verified_at: string;
  milestones: MilestoneVerificationItem[];
}

export interface PipelineTraceItem {
  stage_order: number;
  stage_name: string;
  input_desc: string;
  output_desc: string;
  passed: boolean;
  execution_time_ms: number;
  provenance_intact: boolean;
  details: Record<string, any>;
}

export interface PipelineAuditResponse {
  pipeline_integrity: "VERIFIED" | "DEGRADED" | "BROKEN" | string;
  stages_total: number;
  stages_passed: number;
  total_duration_ms: number;
  synthetic_threat_cve: string;
  provenance_verified: boolean;
  traces: PipelineTraceItem[];
}

export interface ComplianceReport {
  id: number;
  audit_id: string;
  status: "PASSED" | "WARNING" | "FAILED" | string;
  dod_total_criteria: number;
  dod_passed_criteria: number;
  dod_score_pct: number;
  milestones_total: number;
  milestones_passed: number;
  pipeline_integrity: string;
  summary: string;
  executed_by: string;
  execution_time_ms: number;
  audit_timestamp: string;
}

export interface SystemReadinessOverview {
  overall_readiness_score: number;
  readiness_tier: "PRODUCTION_CERTIFIED" | "STAGING_READY" | "IN_DEVELOPMENT" | string;
  dod_passed_criteria: number;
  dod_total_criteria: number;
  milestones_completed: number;
  milestones_total: number;
  pipeline_integrity: string;
  active_sources_count: number;
  active_connectors_count: number;
  security_controls_active: number;
  test_suites_passed_ratio: number;
}

// ── Section 51 (Step 50): Definition of Done Certification Types ─────────────
export interface DoDCertificateProofItem {
  criterion_number: number;
  id: string;
  title: string;
  category: string;
  passed: boolean;
  evidence: string;
  latency_ms: number;
  proof_hash: string;
  verified_at: string;
}

export interface DoDCertificate {
  id?: number;
  certificate_id: string;
  status: "CERTIFIED" | "DEGRADED" | string;
  certified_by: string;
  system_version: string;
  compliance_score_pct: number;
  total_criteria: number;
  passed_criteria: number;
  failed_criteria: number;
  pipeline_integrity: string;
  sha256_signature: string;
  executed_by: string;
  issued_at: string;
  checklist_proofs?: DoDCertificateProofItem[];
  markdown_certificate?: string;
}

export interface DoDCertificateVerification {
  valid: boolean;
  certificate_id: string;
  status: "VERIFIED" | "INVALID_SIGNATURE" | "CORRUPTED" | string;
  message: string;
}

// ── Section 52 (Step 51): Critical Engineering Architecture Types ────────────
export interface DAGNodeInfo {
  id: string;
  name: string;
  layer: number;
  branch: string;
  description: string;
  contract: string;
  anti_pattern_role: string;
}

export interface DAGEdgeInfo {
  source: string;
  target: string;
}

export interface DAGSplitInfo {
  name: string;
  split_from: string;
  branches: string[];
  join_to: string;
}

export interface DAGTopology {
  title: string;
  specification: string;
  prohibited_anti_pattern: string;
  nodes_count: number;
  edges_count: number;
  nodes: DAGNodeInfo[];
  edges: DAGEdgeInfo[];
  triad_splits: DAGSplitInfo[];
}

export interface ArchitectureStageTrace {
  stage_id: string;
  stage_name: string;
  layer: number;
  branch: string;
  status: string;
  passed: boolean;
  execution_time_ms: number;
  provenance_hash: string;
  provenance_intact: boolean;
  input_contract: string;
  output_contract: string;
  details?: Record<string, any>;
}

export interface ArchitectureAntiPatternGuardItem {
  guard_id: string;
  name: string;
  prohibited_action: string;
  status: string;
  prevented: boolean;
  enforcement_mechanism: string;
  evidence: string;
}

export interface ArchitectureAntiPatternResponse {
  anti_pattern_guard_status: string;
  prohibited_architecture: string;
  guards_total: number;
  guards_enforced: number;
  all_anti_patterns_blocked: boolean;
  guards: ArchitectureAntiPatternGuardItem[];
}

export interface ArchitectureAuditRecord {
  id?: number;
  audit_id: string;
  audit_timestamp: string;
  architecture_status: "COMPLIANT" | "VIOLATED" | string;
  stages_count: number;
  stages_passed: number;
  triad_processing_passed: boolean;
  triad_delivery_passed: boolean;
  provenance_intact: boolean;
  anti_patterns_checked: number;
  anti_patterns_prevented: number;
  prohibited_architecture: string;
  target_cve: string;
  source_name: string;
  execution_time_ms: number;
  dag_traces?: ArchitectureStageTrace[];
  anti_patterns?: ArchitectureAntiPatternGuardItem[];
  executed_by: string;
}

export interface PluggableSourceTestRequest {
  custom_source_name: string;
  custom_url: string;
  custom_payload?: string;
}

export interface PluggableSourceTestResult {
  pluggable_source_test_status: string;
  custom_source_name: string;
  custom_url: string;
  zero_code_change_verified: boolean;
  schema_modification_required: boolean;
  api_modification_required: boolean;
  frontend_modification_required: boolean;
  stages_traversed: number;
  stages_passed: number;
  execution_time_ms: number;
  provenance_hash: string;
  triad_processing_verified: boolean;
  triad_delivery_verified: boolean;
  message: string;
}

// Section 53 (Step 52): Immediate First Milestone Golden Pipeline Interfaces
export interface GoldenPipelineStepTrace {
  step_order: number;
  step_name: string;
  layer: string;
  status: string;
  passed: boolean;
  execution_time_ms: number;
  output_contract: string;
  details?: Record<string, any>;
}

export interface GoldenPipelineStepSpec {
  step_order: number;
  step_name: string;
  layer: string;
  component: string;
  description: string;
  contract: string;
  anti_pattern_role: string;
}

export interface GoldenPipelineSpecification {
  title: string;
  section: string;
  pipeline_sequence: string;
  total_steps: number;
  steps: GoldenPipelineStepSpec[];
}

export interface GoldenPipelineRunRequest {
  feed_source?: string;
  target_cve?: string;
  persist?: boolean;
}

export interface GoldenPipelineRunResult {
  run_id: string;
  run_timestamp: string;
  status: "PASSED" | "FAILED" | string;
  feed_source: string;
  article_title: string;
  target_cve: string;
  extracted_cves: string[];
  classification_category: string;
  content_hash: string;
  steps_total: number;
  steps_passed: number;
  total_duration_ms: number;
  search_query_latency_ms: number;
  step_traces: GoldenPipelineStepTrace[];
  message: string;
}


