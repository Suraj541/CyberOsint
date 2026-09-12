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
  content_type: "article" | "cve" | "advisory" | "tool" | "video" | "paper" | "report" | "document";
  source: string;
  category: string;
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
}

export interface SearchResponse {
  total: number;
  page: number;
  page_size: number;
  hits: SearchHitItem[];
  facets?: Record<string, SearchFacetItem[]>;
  took_ms: number;
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


