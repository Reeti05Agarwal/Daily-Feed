# ti-pipeline

Turns a merged security RSS feed into enriched, Obsidian-friendly Markdown notes:

```
feed.xml → noise filter → Claude triage → NVD / CISA KEV / EPSS → PoC lookup → Vulhub check → notes
```

## What you get

- `notes/cves/CVE-XXXX-XXXXX.md`: one note per CVE with CVSS, CWE, EPSS, KEV status, public PoC
  links (unreviewed, as checkboxes), a Vulhub lab link if one exists, a lab checklist, and
  LLM-suggested ATT&CK techniques. When another outlet covers the same CVE, it's appended under Sources.
- `notes/<category>/DATE-title.md`: notes for APT, campaign, malware, breach and research stories.
- `notes/digests/DATE.md`: everything new, sorted by priority.

**Priority:** P1 = exploited in the wild, in CISA KEV, or public PoC exists · P2 = CVSS ≥ 9,
EPSS ≥ 0.5, or attributed APT · P3 = everything else.

## Run locally

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # optional: without it, a regex fallback handles CVE stories only
export NVD_API_KEY=...                # optional, free: https://nvd.nist.gov/developers/request-an-api-key
python -m ti_pipeline.main --limit 5  # start small
```

`git` must be installed (used to index Vulhub without GitHub API rate limits).

## Run on a schedule with GitHub Actions

1. Push this folder to a new **private** GitHub repo (your lab notes belong in private).
2. Settings → Secrets and variables → Actions:
   - Secret `ANTHROPIC_API_KEY` (required for good triage)
   - Secret `NVD_API_KEY` (optional, makes runs ~10x faster)
   - Variable `TI_FEED_URL` (optional, set to your fork's feed URL)
3. Actions tab → ti-pipeline → **Run workflow** to test. After that it runs every 6 hours and
   commits new notes to the repo. Clone or pull the repo into your Obsidian vault folder.

## Configuration

Everything is in `ti_pipeline/config.py`: the noise title patterns, max CVEs noted per article
(default 5, so Patch Tuesday roundups don't create hundreds of notes), and the model.

## Safety

- The pipeline **never downloads or runs PoCs**. It only records links.
- Fake GitHub PoCs that infect researchers are common. Review every line, then run only in an
  isolated VM with snapshots and a host-only network.
- Article text is treated as untrusted data; the model can only return a fixed JSON schema.
- CVE IDs the model returns are dropped unless they literally appear in the article, and
  technique IDs are format-checked. ATT&CK mappings are still suggestions: verify them.

## Not yet built

- Validating technique IDs and names against the official ATT&CK STIX data
- Pulling ATT&CK group pages and aliases into APT notes
- Clustering non-CVE stories covered by several outlets into one note
