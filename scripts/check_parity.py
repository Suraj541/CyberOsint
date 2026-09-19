import sqlite3
import urllib.request
import json

def main():
    conn = sqlite3.connect('cyber_osint_dev.db')
    c = conn.cursor()

    c.execute('SELECT COUNT(*) FROM content')
    db_content = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM entities WHERE entity_type = 'cve'")
    db_cves = c.fetchone()[0]

    c.execute('SELECT COUNT(*) FROM sources')
    db_sources = c.fetchone()[0]

    c.execute('SELECT COUNT(*) FROM entities')
    db_entities = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM content WHERE content_type = 'advisory'")
    db_advisories = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM content WHERE content_type IN ('paper', 'research')")
    db_research = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM content WHERE content_type = 'video'")
    db_videos = c.fetchone()[0]

    conn.close()

    req = urllib.request.Request('http://127.0.0.1:8000/api/v1/dashboard', headers={'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode('utf-8'))

    metrics = data.get('metrics', {})

    print(f"DB Total Content: {db_content} | Dashboard Metric total_content: {metrics.get('total_content')}")
    print(f"DB CVE Entities: {db_cves} | Dashboard Metric tracked_cves: {metrics.get('tracked_cves')}")
    print(f"DB Total Sources: {db_sources} | Dashboard Metric active_sources: {metrics.get('active_sources')}")
    print(f"DB Advisories: {db_advisories} | Dashboard Metric threat_advisories: {metrics.get('threat_advisories')}")
    print(f"DB Research: {db_research} | Dashboard Metric research_papers: {metrics.get('research_papers')}")
    print(f"DB Videos: {db_videos} | Dashboard Metric indexed_videos: {metrics.get('indexed_videos')}")

if __name__ == '__main__':
    main()
