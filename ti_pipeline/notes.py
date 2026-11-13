"""Write Obsidian-friendly Markdown notes.

- One note per CVE. If 8 outlets cover the same CVE, you get one note with 8 sources.
- One note per non-CVE story (APT, campaign, malware, ...).
- A digest per day linking everything new.
"""
import re
from datetime import date
from pathlib import Path

from . import config

POC_WARNING = ("> ⚠️ Unreviewed links. Fake PoCs that drop malware on researchers are common. "
               "Read every line before running, and only run inside an isolated lab VM.")


def _slug(text: str, n: int = 60) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:n] or "untitled"


def _attack_url(tid: str) -> str:
    return f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"


def _bullets(items, empty="_none stated_"):
    return "\n".join(f"- {i}" for i in items) if items else empty


def _source_line(item: dict) -> str:
    return f"- [{item['title']}]({item['link']}) — {item['source']}, {item['published']}"


def _techniques(cls: dict) -> str:
    if not cls["attack_techniques"]:
        return "_none extracted_"
    rows = ["| ID | Technique | Evidence |", "|---|---|---|"]
    for t in cls["attack_techniques"]:
        rows.append(f"| [{t['id']}]({_attack_url(t['id'])}) | {t['name']} | {t['evidence']} |")
    return "\n".join(rows)


def _write(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path.relative_to(config.NOTES_DIR))


def append_source(rel_path: str, item: dict) -> None:
    """Sources is the last section, so adding another outlet's coverage is a plain append."""
    path = config.NOTES_DIR / rel_path
    if path.exists() and item["link"] not in path.read_text(encoding="utf-8"):
        with path.open("a", encoding="utf-8") as f:
            f.write(_source_line(item) + "\n")


def write_cve_note(info: dict, cls: dict, item: dict, prio: str) -> str:
    cve, nvd, kev, epss = info["cve"], info["nvd"] or {}, info["kev"], info["epss"]
    cvss = nvd.get("cvss") or {}

    severity = "\n".join([
        "| CVSS | Vector | EPSS | CISA KEV |",
        "|---|---|---|---|",
        "| {} | `{}` | {} | {} |".format(
            f"{cvss.get('score')} {cvss.get('severity', '')} (v{cvss.get('version')})" if cvss else "n/a",
            cvss.get("vector", "n/a"),
            f"{epss['score']:.3f} (p{epss['percentile'] * 100:.0f})" if epss else "n/a",
            f"**YES**, added {kev['dateAdded']}, ransomware use: {kev.get('knownRansomwareCampaignUse', '?')}"
            if kev else "no",
        ),
    ])

    pocs = info["pocs"]
    if pocs:
        poc_lines = [POC_WARNING, ""]
        for p in pocs[:10]:
            stars = f"⭐{p['stars']} " if p["stars"] is not None else ""
            desc = f" — {p['description']}" if p["description"] else ""
            poc_lines.append(f"- [ ] reviewed · {stars}{p['url']}{desc}")
        if len(pocs) > 10:
            poc_lines.append(f"- …and {len(pocs) - 10} more")
    else:
        poc_lines = ["_No public PoC indexed yet._"]
    if nvd.get("exploit_refs"):
        poc_lines += ["", "NVD references tagged *Exploit*:", _bullets(nvd["exploit_refs"])]

    lab = (f"Vulhub environment available: {info['vulhub']}" if info["vulhub"]
           else "No Vulhub environment. Build manually (Docker/VM with the exact vulnerable version).")

    body = f"""---
tags: [cve, {cls['category']}, {prio}]
cve: {cve}
priority: {prio}
first_seen: {date.today().isoformat()}
---
# {cve} — {item['title']}

**Priority:** {prio} · **Category:** {cls['category']} · **Exploited in the wild (per article):** {'yes' if cls['exploited_in_wild'] else 'not stated'} · _triage: {cls['classified_by']}_

## Summary
{cls['summary']}

## Root cause
- **CWE (NVD):** {', '.join(nvd.get('cwes', [])) or 'n/a'}
- **Article:** {cls['root_cause'] or '_not stated_'}
- **NVD description:** {nvd.get('description') or '_not in NVD yet_'}
- **Patch diff notes:** _TODO: find the fix commit and read it_

## Affected products
{_bullets(cls['products'])}

## Severity & exploitation
{severity}

## Public PoCs
{chr(10).join(poc_lines)}

## Lab
{lab}

- [ ] Environment built (snapshot taken, host-only network)
- [ ] Exploit reproduced
- [ ] Patched version confirmed not vulnerable
- [ ] Detection written (Sigma / Suricata / YARA)

## MITRE ATT&CK (LLM-suggested, verify)
{_techniques(cls)}

## Detection notes
_TODO_

## References
{_bullets(nvd.get('references', [])[:10], '_n/a_')}

## Sources
{_source_line(item)}
"""
    return _write(config.NOTES_DIR / "cves" / f"{cve}.md", body)


def write_story_note(cls: dict, item: dict, prio: str, noted_cves: list[str]) -> str:
    folder = cls["category"]
    name = f"{date.today().isoformat()}-{_slug(item['title'])}.md"
    body = f"""---
tags: [{cls['category']}, {prio}]
priority: {prio}
first_seen: {date.today().isoformat()}
---
# {item['title']}

**Priority:** {prio} · **Category:** {cls['category']} · _triage: {cls['classified_by']}_

## Summary
{cls['summary']}

## Threat actors
{_bullets(cls['threat_actors'])}

## Malware / tools
{_bullets(cls['malware'])}

## Targeted products
{_bullets(cls['products'])}

## CVEs mentioned
{_bullets([f'[[{c}]]' if c in noted_cves else c for c in cls['cves']])}

## MITRE ATT&CK (LLM-suggested, verify)
{_techniques(cls)}

## Analyst notes
_TODO: find the primary vendor report, check ATT&CK group page for aliases, list IOCs._

## Sources
{_source_line(item)}
"""
    return _write(config.NOTES_DIR / folder / name, body)


def write_digest(entries: list[dict]) -> str:
    """entries: dicts with priority, title, link, category, note_path, cves."""
    path = config.NOTES_DIR / "digests" / f"{date.today().isoformat()}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [] if path.exists() else [f"# Threat intel digest — {date.today().isoformat()}", ""]
    for e in sorted(entries, key=lambda e: (e["priority"] or "P9", e["category"])):
        note = f" → [note](../{e['note_path']})" if e["note_path"] else ""
        cves = f" · {', '.join(e['cves'])}" if e["cves"] else ""
        lines.append(f"- **{e['priority']}** [{e['category']}] [{e['title']}]({e['link']}){cves}{note}")
    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return str(path)
