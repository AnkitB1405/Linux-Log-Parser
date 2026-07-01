# Graph Report - Log_Parser  (2026-07-01)

## Corpus Check
- 5 files · ~1,870 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 39 nodes · 56 edges · 7 communities (4 shown, 3 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `9c8ed086`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]

## God Nodes (most connected - your core abstractions)
1. `identify_event()` - 12 edges
2. `parse_timestamp()` - 10 edges
3. `Homelab Log Parser (Linux)` - 6 edges
4. `Roadmap` - 6 edges
5. `parse_failed_login()` - 4 edges
6. `parse_successful_login()` - 4 edges
7. `V1` - 4 edges
8. `parse_session_opened()` - 3 edges
9. `parse_invalid_user()` - 3 edges
10. `parse_connection_closed()` - 3 edges

## Surprising Connections (you probably didn't know these)
- `parse_failed_login()` --calls--> `parse_timestamp()`  [EXTRACTED]
  parser/ssh_parser.py → parser/ssh_parser.py  _Bridges community 0 → community 3_
- `parse_successful_login()` --calls--> `parse_timestamp()`  [EXTRACTED]
  parser/ssh_parser.py → parser/ssh_parser.py  _Bridges community 0 → community 4_

## Import Cycles
- None detected.

## Communities (7 total, 3 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.44
Nodes (10): identify_event(), parse_auth_failure(), parse_connection_closed(), parse_invalid_user(), parse_multiple_failures(), parse_service_started(), parse_service_stopped(), parse_session_opened() (+2 more)

### Community 5 - "Community 5"
Cohesion: 0.20
Nodes (9): Current Features, Detection Engine, Graphify Support, Homelab Log Parser (Linux), Objectives, Project Structure, SSH Brute Force, SSH Parser (+1 more)

### Community 6 - "Community 6"
Cohesion: 0.22
Nodes (9): Alerting, Author, Design Philosophy, Detectors, Parsers, Roadmap, Status, V1 (+1 more)

## Knowledge Gaps
- **13 isolated node(s):** `Objectives`, `SSH Parser`, `SSH Brute Force`, `Project Structure`, `Workflow` (+8 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Roadmap` connect `Community 6` to `Community 5`?**
  _High betweenness centrality (0.145) - this node is a cross-community bridge._
- **Why does `identify_event()` connect `Community 0` to `Community 1`, `Community 3`, `Community 4`?**
  _High betweenness centrality (0.071) - this node is a cross-community bridge._
- **What connects `Extract username and source IP     from a failed SSH login event.`, `Extract username and source IP     from a successful SSH login event.`, `Identify the SSH event type from a log line.` to the rest of the system?**
  _16 weakly-connected nodes found - possible documentation gaps or missing edges._