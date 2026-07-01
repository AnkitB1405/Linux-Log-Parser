# Graph Report - Log_Parser  (2026-07-01)

## Corpus Check
- 4 files · ~1,329 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 20 nodes · 38 edges · 6 communities (3 shown, 3 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `4b7fc56e`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]

## God Nodes (most connected - your core abstractions)
1. `identify_event()` - 12 edges
2. `parse_timestamp()` - 10 edges
3. `parse_failed_login()` - 4 edges
4. `parse_successful_login()` - 4 edges
5. `parse_session_opened()` - 3 edges
6. `parse_invalid_user()` - 3 edges
7. `parse_connection_closed()` - 3 edges
8. `parse_auth_failure()` - 3 edges
9. `parse_multiple_failures()` - 3 edges
10. `parse_service_started()` - 3 edges

## Surprising Connections (you probably didn't know these)
- `parse_auth_failure()` --calls--> `parse_timestamp()`  [EXTRACTED]
  parser/ssh_parser.py → parser/ssh_parser.py  _Bridges community 0 → community 5_
- `parse_failed_login()` --calls--> `parse_timestamp()`  [EXTRACTED]
  parser/ssh_parser.py → parser/ssh_parser.py  _Bridges community 0 → community 3_
- `parse_successful_login()` --calls--> `parse_timestamp()`  [EXTRACTED]
  parser/ssh_parser.py → parser/ssh_parser.py  _Bridges community 0 → community 4_
- `identify_event()` --calls--> `parse_failed_login()`  [EXTRACTED]
  parser/ssh_parser.py → parser/ssh_parser.py  _Bridges community 3 → community 5_
- `identify_event()` --calls--> `parse_successful_login()`  [EXTRACTED]
  parser/ssh_parser.py → parser/ssh_parser.py  _Bridges community 4 → community 5_

## Import Cycles
- None detected.

## Communities (6 total, 3 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.52
Nodes (6): parse_connection_closed(), parse_invalid_user(), parse_multiple_failures(), parse_service_stopped(), parse_session_opened(), parse_timestamp()

### Community 5 - "Community 5"
Cohesion: 0.50
Nodes (4): identify_event(), parse_auth_failure(), parse_service_started(), Identify the SSH event type from a log line.

## Knowledge Gaps
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `identify_event()` connect `Community 5` to `Community 0`, `Community 1`, `Community 3`, `Community 4`?**
  _High betweenness centrality (0.293) - this node is a cross-community bridge._
- **Why does `parse_timestamp()` connect `Community 0` to `Community 3`, `Community 4`, `Community 5`?**
  _High betweenness centrality (0.103) - this node is a cross-community bridge._
- **Why does `parse_failed_login()` connect `Community 3` to `Community 0`, `Community 5`?**
  _High betweenness centrality (0.095) - this node is a cross-community bridge._
- **What connects `Extract username and source IP     from a failed SSH login event.`, `Extract username and source IP     from a successful SSH login event.`, `Identify the SSH event type from a log line.` to the rest of the system?**
  _3 weakly-connected nodes found - possible documentation gaps or missing edges._