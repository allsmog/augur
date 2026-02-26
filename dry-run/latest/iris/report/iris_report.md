# Augur IRIS Report

Generated at: `2026-02-26T16:21:01.031864+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 1 | 1 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 1 | 1 | 0 | 0 | 0 |
| 3 | SSRF | 1 | 1 | 0 | 0 | 0 |
| 4 | Code Injection | 1 | 1 | 0 | 0 | 0 |
| 5 | SQL Injection | 1 | 1 | 0 | 0 | 0 |
| 6 | Unsafe Deserialization | 1 | 1 | 0 | 0 | 0 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 3 | SSRF | 7 | 0 | 7 | 0 |
| 6 | Unsafe Deserialization | 1 | 0 | 1 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass3` `app/main.py:21` `py/augur/pass3-ssrf`: Potential SSRF flow from [source](1) to [sink](2).
Potential SSRF flow from [source](3) to [sink](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `app/main.py:10` `py/augur/pass3-ssrf`: Potential SSRF flow from [source](1) to [sink](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `app/main.py:15` `py/augur/pass3-ssrf`: Potential SSRF flow from [source](1) to [sink](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `app/main.py:19` `py/augur/pass3-ssrf`: Potential SSRF flow from [source](1) to [sink](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `app/main.py:23` `py/augur/pass3-ssrf`: Potential SSRF flow from [source](1) to [sink](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `app/main.py:27` `py/augur/pass3-ssrf`: Potential SSRF flow from [source](1) to [sink](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `app/main.py:35` `py/augur/pass3-ssrf`: Potential SSRF flow from [source](1) to [sink](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass6` `app/main.py:37` `py/augur/pass6-unsafe-deserialization`: Potential unsafe deserialization flow from [source](1) to [sink](2).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
