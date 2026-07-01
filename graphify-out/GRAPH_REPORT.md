# Graph Report - Log_Parser  (2026-07-01)

## Corpus Check
- 4 files · ~1,076 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 19 nodes · 28 edges · 5 communities (2 shown, 3 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `f06ae10f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]

## God Nodes (most connected - your core abstractions)
1. `identify_event()` - 12 edges
2. `parse_failed_login()` - 3 edges
3. `parse_successful_login()` - 3 edges
4. `detect_bruteforce()` - 2 edges
5. `parse_session_opened()` - 2 edges
6. `parse_invalid_user()` - 2 edges
7. `parse_connection_closed()` - 2 edges
8. `parse_auth_failure()` - 2 edges
9. `parse_multiple_failures()` - 2 edges
10. `parse_service_started()` - 2 edges

## Surprising Connections (you probably didn't know these)
- `identify_event()` --calls--> `parse_failed_login()`  [EXTRACTED]
  parser/ssh_parser.py → parser/ssh_parser.py  _Bridges community 3 → community 0_
- `identify_event()` --calls--> `parse_successful_login()`  [EXTRACTED]
  parser/ssh_parser.py → parser/ssh_parser.py  _Bridges community 4 → community 0_

## Import Cycles
- None detected.

## Communities (5 total, 3 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.36
Nodes (9): identify_event(), parse_auth_failure(), parse_connection_closed(), parse_invalid_user(), parse_multiple_failures(), parse_service_started(), parse_service_stopped(), parse_session_opened() (+1 more)

## Knowledge Gaps
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `identify_event()` connect `Community 0` to `Community 1`, `Community 3`, `Community 4`?**
  _High betweenness centrality (0.379) - this node is a cross-community bridge._
- **Why does `parse_failed_login()` connect `Community 3` to `Community 0`?**
  _High betweenness centrality (0.098) - this node is a cross-community bridge._
- **Why does `parse_successful_login()` connect `Community 4` to `Community 0`?**
  _High betweenness centrality (0.098) - this node is a cross-community bridge._
- **What connects `Extract username and source IP     from a failed SSH login event.`, `Extract username and source IP     from a successful SSH login event.`, `Identify the SSH event type from a log line.` to the rest of the system?**
  _3 weakly-connected nodes found - possible documentation gaps or missing edges._