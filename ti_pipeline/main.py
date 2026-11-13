"""Run the pipeline: python -m ti_pipeline.main [--limit N] [--feed URL_OR_FILE]"""
import argparse
import logging

import requests

from . import classify, config, db, enrich, ingest, notes

log = logging.getLogger("ti_pipeline")


def process(item, conn, session, enricher) -> dict | None:
    if ingest.is_noise_title(item["title"]):
        db.mark_item(conn, item, "noise")
        log.info("noise (title)  %s", item["title"])
        return None

    text = ingest.fetch_article_text(item["link"], session)
    cls = classify.classify(item["title"], text)
    if cls["category"] == "noise":
        db.mark_item(conn, item, "noise")
        log.info("noise (model)  %s", item["title"])
        return None

    # CVEs that already have a note just get this outlet appended as a source;
    # only genuinely new CVEs spend NVD/EPSS/PoC lookups.
    existing = {c: db.cve_note(conn, c) for c in cls["cves"]}
    known = {c: v for c, v in existing.items() if v}
    fresh = [c for c in cls["cves"] if c not in known]

    cve_infos = enricher.enrich_cves(fresh) if fresh else []
    prio = enrich.priority(cls, cve_infos)
    if known:
        prio = min([prio] + [p for _, p in known.values() if p])  # "P1" < "P2" < "P3"

    noted, note_paths = [], []
    for cve, (path, _) in known.items():
        notes.append_source(path, item)
        noted.append(cve)
        note_paths.append(path)
    for info in cve_infos:
        path = notes.write_cve_note(info, cls, item, prio)
        db.add_cve_note(conn, info["cve"], path, prio)
        noted.append(info["cve"])
        note_paths.append(path)

    # Story note for non-vuln stories, or vuln roundups with more CVEs than we noted.
    if cls["category"] != "vulnerability" or len(cls["cves"]) > len(noted):
        note_paths.insert(0, notes.write_story_note(cls, item, prio, noted))

    main_note = note_paths[0] if note_paths else ""
    db.mark_item(conn, item, cls["category"], prio, main_note)
    log.info("%s %-13s %s", prio, cls["category"], item["title"])
    return {"priority": prio, "category": cls["category"], "title": item["title"],
            "link": item["link"], "note_path": main_note, "cves": cls["cves"][:5]}


def main():
    ap = argparse.ArgumentParser(description="Threat-intel feed → enriched Markdown notes")
    ap.add_argument("--feed", default=config.FEED_URL, help="feed URL or local XML file")
    ap.add_argument("--limit", type=int, default=0, help="max new items this run (0 = all)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")

    session = requests.Session()
    session.headers["User-Agent"] = config.USER_AGENT
    conn = db.connect()
    enricher = enrich.Enricher(session)

    items = ingest.fetch_feed(args.feed, session)
    new = [i for i in items if not db.is_seen(conn, i["link"])]
    if args.limit:
        new = new[: args.limit]
    log.info("%d items in feed, %d new", len(items), len(new))

    digest = []
    for item in new:
        try:
            entry = process(item, conn, session, enricher)
        except Exception:  # one bad article shouldn't kill the run; it's retried next run
            log.exception("Failed on %s", item["link"])
            continue
        if entry:
            digest.append(entry)

    if digest:
        log.info("Digest: %s", notes.write_digest(digest))
    conn.close()


if __name__ == "__main__":
    main()
