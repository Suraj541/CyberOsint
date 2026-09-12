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

export interface ContentItem {
  id: number;
  title: string;
  description?: string;
  summary?: string;
  canonical_url: string;
  content_type: "article" | "cve" | "advisory" | "tool" | "video" | "paper" | "report";
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

