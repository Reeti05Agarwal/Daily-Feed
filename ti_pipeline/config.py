"""All tunable settings. Override any of them with environment variables."""
import os
from pathlib import Path

# Point this at your fork's GitHub Pages feed once you've forked Threat-Intel-Feed.
# ("or" so an empty env var, e.g. an unset GitHub Actions variable, falls back to the default.)
FEED_URL = os.getenv("TI_FEED_URL") or "https://endlessfractal.github.io/Threat-Intel-Feed/feed.xml"

# Cheap, fast model is plenty for classification + extraction.
MODEL = os.getenv("TI_MODEL") or "claude-haiku-5-5"

NVD_API_KEY = os.getenv("NVD_API_KEY") or None    # optional: raises NVD limit from 5 to 50 req / 30s

DATA_DIR = Path(os.getenv("TI_DATA_DIR", "data"))
NOTES_DIR = Path(os.getenv("TI_NOTES_DIR", "notes"))
DB_PATH = DATA_DIR / "pipeline.db"

MAX_ARTICLE_CHARS = 15_000      # article text sent to the model
MAX_CVES_PER_ARTICLE = 5        # Patch Tuesday posts mention hundreds; only note the top ones
HTTP_TIMEOUT = 30
USER_AGENT = "ti-pipeline/0.1 (personal threat-intel research)"

# Skipped before any API call is spent on them (case-insensitive regex on the title).
NOISE_TITLE_PATTERNS = [
    r"stormcast",
    r"podcast",
    r"^how to export",
    r"webinar",
    r"\| letters",
]

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
NOMI_SEC_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
TRICKEST_URL = "https://raw.githubusercontent.com/trickest/cve/main/{year}/{cve}.md"
VULHUB_REPO = "https://github.com/vulhub/vulhub.git"  # indexed via blobless clone, no API limits
VULHUB_INDEX_MAX_AGE_HOURS = 24
