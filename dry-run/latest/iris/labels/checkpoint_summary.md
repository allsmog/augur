# Checkpoint Summary

- Label counts by pass/role provided in `label_stats.md`.
- High-risk sinks: `open`, `subprocess.run`, `requests.get`, `eval`, `cursor.execute`, `pickle.loads`.
- Broad sources: FastAPI `Query` boundary usage.
- Sanitizers: none in this synthetic target.
- Low-confidence items: none (<0.55 threshold).
