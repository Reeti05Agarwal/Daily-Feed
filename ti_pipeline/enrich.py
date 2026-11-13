"""CVE enrichment from free public sources.

PoC lookups only COLLECT LINKS. Nothing is downloaded or executed: review every PoC by hand
and run it only in an isolated lab. Fake "PoC" repos carrying malware are a known trap.
"""
import json
import logging
import re
import subprocess
import tempfile
import time
from pathlib import Path

import requests

from . import config

log = logging.getLogger(__name__)
CVE_DIR_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
URL_RE = re.compile(r"https?://[^\s)\]>]+")


class Enricher:
    def __init__(self, session: requests.Session):
        self.s = session
        self._kev = None
        self._vulhub = None
        self._last_nvd_call = 0.0
        # NVD public limits: 5 req / 30s without a key, 50 / 30s with one.
        self._nvd_gap = 0.7 if config.NVD_API_KEY else 6.5

    # ---------- generic ----------
    def _get(self, url, **kw):
        try:
            resp = self.s.get(url, timeout=config.HTTP_TIMEOUT, **kw)
        except requests.RequestException as exc:
            log.warning("GET %s failed: %s", url, exc)
            return None
        if resp.status_code == 404:
            return None
        if not resp.ok:
            log.warning("GET %s -> HTTP %s", url, resp.status_code)
            return None
        return resp

    # ---------- CISA KEV ----------
    def kev(self) -> dict:
        if self._kev is None:
            resp = self._get(config.KEV_URL)
            vulns = resp.json().get("vulnerabilities", []) if resp else []
            self._kev = {v["cveID"].upper(): v for v in vulns}
            log.info("Loaded %d KEV entries", len(self._kev))
        return self._kev

    # ---------- NVD ----------
    def nvd(self, cve: str):
        wait = self._nvd_gap - (time.monotonic() - self._last_nvd_call)
        if wait > 0:
            time.sleep(wait)
        self._last_nvd_call = time.monotonic()

        headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
        resp = self._get(config.NVD_URL, params={"cveId": cve}, headers=headers)
        vulns = resp.json().get("vulnerabilities", []) if resp else []
        if not vulns:
            return None  # brand-new CVEs often aren't in NVD yet
        c = vulns[0]["cve"]

        cvss = None
        metrics = c.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if metrics.get(key):
                d = metrics[key][0]["cvssData"]
                cvss = {"version": d.get("version"), "score": d.get("baseScore"),
                        "severity": d.get("baseSeverity"), "vector": d.get("vectorString")}
                break

        return {
            "description": next((d["value"] for d in c.get("descriptions", [])
                                 if d.get("lang") == "en"), ""),
            "published": c.get("published", ""),
            "status": c.get("vulnStatus", ""),
            "cvss": cvss,
            "cwes": sorted({d["value"] for w in c.get("weaknesses", [])
                            for d in w.get("description", [])
                            if d.get("value", "").startswith("CWE-")}),
            "references": [r["url"] for r in c.get("references", [])][:15],
            "exploit_refs": [r["url"] for r in c.get("references", [])
                             if "Exploit" in r.get("tags", [])],
        }

    # ---------- EPSS ----------
    def epss(self, cves: list[str]) -> dict:
        if not cves:
            return {}
        resp = self._get(config.EPSS_URL, params={"cve": ",".join(cves)})
        rows = resp.json().get("data", []) if resp else []
        return {r["cve"].upper(): {"score": float(r["epss"]), "percentile": float(r["percentile"])}
                for r in rows}

    # ---------- public PoCs ----------
    def pocs(self, cve: str) -> list[dict]:
        year = cve.split("-")[1]
        found: dict[str, dict] = {}

        resp = self._get(config.NOMI_SEC_URL.format(year=year, cve=cve))
        if resp:
            try:
                for r in resp.json():
                    found[r["html_url"].rstrip("/").lower()] = {
                        "url": r["html_url"],
                        "stars": r.get("stargazers_count", 0),
                        "description": (r.get("description") or "")[:140],
                        "created": (r.get("created_at") or "")[:10],
                        "via": "nomi-sec",
                    }
            except (ValueError, KeyError, TypeError) as exc:
                log.warning("Bad nomi-sec data for %s: %s", cve, exc)

        resp = self._get(config.TRICKEST_URL.format(year=year, cve=cve))
        if resp and "#### Github" in resp.text:
            github_section = resp.text.split("#### Github", 1)[1]
            for url in URL_RE.findall(github_section):
                key = url.rstrip("/").lower()
                if "github.com/" in key and key not in found:
                    found[key] = {"url": url, "stars": None, "description": "",
                                  "created": "", "via": "trickest"}

        # Most-starred first; stars are a weak trust signal, never a guarantee.
        return sorted(found.values(), key=lambda p: p["stars"] or 0, reverse=True)

    # ---------- Vulhub lab environments ----------
    def vulhub(self, cve: str):
        if self._vulhub is None:
            self._vulhub = self._load_vulhub_index()
        path = self._vulhub.get(cve.upper())
        return f"https://github.com/vulhub/vulhub/tree/master/{path}" if path else None

    def _load_vulhub_index(self) -> dict:
        cache = config.DATA_DIR / "vulhub_index.json"
        if cache.exists() and time.time() - cache.stat().st_mtime < config.VULHUB_INDEX_MAX_AGE_HOURS * 3600:
            return json.loads(cache.read_text())

        index = {}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                # Blobless, no-checkout clone: downloads only the tree (~400 KB), no API rate limits.
                subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none",
                                "--no-checkout", config.VULHUB_REPO, tmp],
                               check=True, timeout=120, capture_output=True)
                out = subprocess.run(["git", "-C", tmp, "ls-tree", "-r", "-d", "--name-only", "HEAD"],
                                     check=True, capture_output=True, text=True).stdout
            for path in out.splitlines():
                m = CVE_DIR_RE.search(Path(path).name)  # also matches e.g. PIL-CVE-2017-8291
                if m:
                    index.setdefault(m.group(0).upper(), path)
        except (subprocess.SubprocessError, OSError) as exc:
            log.warning("Vulhub index unavailable: %s", exc)
            if cache.exists():
                return json.loads(cache.read_text())
            return {}

        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(index, indent=0))
        log.info("Indexed %d Vulhub CVE environments", len(index))
        return index

    # ---------- everything for one article ----------
    def enrich_cves(self, cves: list[str]) -> list[dict]:
        kev = self.kev()
        # Notes only for the most important CVEs: KEV-listed ones first.
        chosen = sorted(cves, key=lambda c: (c not in kev, c))[: config.MAX_CVES_PER_ARTICLE]
        epss = self.epss(chosen)
        results = []
        for cve in chosen:
            results.append({
                "cve": cve,
                "kev": kev.get(cve),
                "nvd": self.nvd(cve),
                "epss": epss.get(cve),
                "pocs": self.pocs(cve),
                "vulhub": self.vulhub(cve),
            })
        return results


def priority(cls: dict, cve_infos: list[dict]) -> str:
    """P1 = exploited or public PoC, P2 = severe or attributed APT, P3 = everything else."""
    if cls["exploited_in_wild"] or any(i["kev"] for i in cve_infos):
        return "P1"
    if any(i["pocs"] or (i["nvd"] and i["nvd"]["exploit_refs"]) for i in cve_infos):
        return "P1"
    for i in cve_infos:
        score = (i["nvd"] or {}).get("cvss") or {}
        if (score.get("score") or 0) >= 9.0 or (i["epss"] or {}).get("score", 0) >= 0.5:
            return "P2"
    if cls["category"] == "apt":
        return "P2"
    return "P3"
