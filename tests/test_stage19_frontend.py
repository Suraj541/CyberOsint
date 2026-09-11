"""
Stage 19 / Section 20: Build Frontend (apps/web/) Baseline Tests
Verifies the Next.js frontend directory structure, configuration files,
all 10 mandated Section 20 route pages, reusable UI components,
and Section 22 content modal conformance.
Conforms to IMPLEMENT.md Section 20, 21, and 22.
"""

import json
from pathlib import Path
import unittest

repo_root = Path(__file__).resolve().parent.parent
web_root = repo_root / "apps" / "web"


class TestStage19FrontendBaseline(unittest.TestCase):
    """Test suite validating Step 19 / Section 20 Frontend Dashboard."""

    def test_frontend_root_and_configs_exist(self):
        """Confirm apps/web contains all essential Next.js and Tailwind configuration files."""
        self.assertTrue(web_root.exists(), "apps/web directory missing")
        self.assertTrue((web_root / "package.json").exists(), "package.json missing")
        self.assertTrue((web_root / "tsconfig.json").exists(), "tsconfig.json missing")
        self.assertTrue((web_root / "tailwind.config.js").exists(), "tailwind.config.js missing")
        self.assertTrue((web_root / "postcss.config.js").exists(), "postcss.config.js missing")
        self.assertTrue((web_root / "next.config.js").exists(), "next.config.js missing")

    def test_package_json_dependencies_and_scripts(self):
        """Confirm package.json specifies required Next.js, React, and Tailwind dependencies."""
        pkg_file = web_root / "package.json"
        with open(pkg_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data.get("name"), "cyber-osint-web")
        scripts = data.get("scripts", {})
        self.assertIn("dev", scripts)
        self.assertIn("build", scripts)
        self.assertIn("start", scripts)

        deps = data.get("dependencies", {})
        self.assertIn("next", deps)
        self.assertIn("react", deps)
        self.assertIn("react-dom", deps)

        dev_deps = data.get("devDependencies", {})
        self.assertIn("tailwindcss", dev_deps)
        self.assertIn("typescript", dev_deps)

    def test_all_ten_mandated_routes_exist(self):
        """
        Confirm all 10 mandated routes from IMPLEMENT.md Section 20 exist:
        /, /search, /news, /research, /vulnerabilities, /tools, /videos, /documents, /intelligence, /sources.
        """
        app_dir = web_root / "app"
        self.assertTrue((app_dir / "layout.tsx").exists(), "app/layout.tsx missing")
        self.assertTrue((app_dir / "globals.css").exists(), "app/globals.css missing")
        self.assertTrue((app_dir / "page.tsx").exists(), "app/page.tsx (Dashboard) missing")

        mandated_routes = [
            "search",
            "news",
            "research",
            "vulnerabilities",
            "tools",
            "videos",
            "documents",
            "intelligence",
            "sources",
        ]
        for route in mandated_routes:
            route_page = app_dir / route / "page.tsx"
            self.assertTrue(
                route_page.exists(),
                f"Mandated Section 20 route page '{route}/page.tsx' does not exist",
            )

    def test_shared_ui_components_exist(self):
        """Confirm all mandated reusable UI components exist."""
        comp_dir = web_root / "components"
        self.assertTrue((comp_dir / "Navbar.tsx").exists(), "Navbar.tsx missing")
        self.assertTrue((comp_dir / "Sidebar.tsx").exists(), "Sidebar.tsx missing")
        self.assertTrue((comp_dir / "StatCard.tsx").exists(), "StatCard.tsx missing")
        self.assertTrue((comp_dir / "ContentCard.tsx").exists(), "ContentCard.tsx missing")
        self.assertTrue((comp_dir / "ContentModal.tsx").exists(), "ContentModal.tsx missing")
        self.assertTrue((comp_dir / "SeverityBadge.tsx").exists(), "SeverityBadge.tsx missing")
        self.assertTrue((comp_dir / "SearchBar.tsx").exists(), "SearchBar.tsx missing")

    def test_lib_types_and_api_client_exist(self):
        """Confirm lib/types.ts and lib/api.ts are present and non-empty."""
        lib_dir = web_root / "lib"
        types_file = lib_dir / "types.ts"
        api_file = lib_dir / "api.ts"
        self.assertTrue(types_file.exists(), "lib/types.ts missing")
        self.assertTrue(api_file.exists(), "lib/api.ts missing")

        with open(types_file, "r", encoding="utf-8") as f:
            types_content = f.read()
        self.assertIn("ContentItem", types_content)
        self.assertIn("VulnerabilityItem", types_content)
        self.assertIn("ThreatIntelligenceItem", types_content)
        self.assertIn("SourceConnectorItem", types_content)
        self.assertIn("DashboardMetrics", types_content)

        with open(api_file, "r", encoding="utf-8") as f:
            api_content = f.read()
        self.assertIn("fetchDashboardMetrics", api_content)
        self.assertIn("fetchRecentContent", api_content)
        self.assertIn("fetchVulnerabilities", api_content)
        self.assertIn("fetchThreatIntelligence", api_content)
        self.assertIn("fetchSources", api_content)
        self.assertIn("executeSearch", api_content)

    def test_section22_content_modal_mandated_fields(self):
        """
        Validate ContentModal.tsx handles all mandated fields from IMPLEMENT.md Section 22:
        Title, Source, Published Date, Author, Category, Tags, Summary, Extracted Entities, Original Source.
        """
        modal_file = web_root / "components" / "ContentModal.tsx"
        with open(modal_file, "r", encoding="utf-8") as f:
            content = f.read()

        mandated_keywords = [
            "title",
            "source",
            "published_at",
            "author",
            "category",
            "tags",
            "summary",
            "entities",
            "canonical_url",
        ]
        for kw in mandated_keywords:
            self.assertIn(kw, content, f"Section 22 field '{kw}' not referenced in ContentModal.tsx")


if __name__ == "__main__":
    unittest.main()
