# Graph Report - Log_Parser  (2026-08-06)

## Corpus Check
- 18 files · ~10,801 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 152 nodes · 214 edges · 11 communities
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `6a942fa6`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]

## God Nodes (most connected - your core abstractions)
1. `identify_event()` - 14 edges
2. `create_event()` - 12 edges
3. `parse_host()` - 11 edges
4. `parse_timestamp()` - 10 edges
5. `Architecture — Homelab Log Parser (Linux)` - 10 edges
6. `Day 1` - 10 edges
7. `Day 2` - 10 edges
8. `Day 3` - 10 edges
9. `Security Considerations — Homelab Log Parser (Linux)` - 9 edges
10. `parse_failed_login()` - 7 edges

## Surprising Connections (you probably didn't know these)
- `build_events()` --calls--> `identify_event()`  [EXTRACTED]
  test_detectors.py → parser/ssh_parser.py
- `run_detectors()` --calls--> `detect_behavior()`  [EXTRACTED]
  test_detectors.py → detectors/behavior.py
- `run_detectors()` --calls--> `detect_bruteforce()`  [EXTRACTED]
  test_detectors.py → detectors/bruteforce.py
- `run_detectors()` --calls--> `detect_service_anomaly()`  [EXTRACTED]
  test_detectors.py → detectors/service_anomaly.py
- `run_detectors()` --calls--> `detect_session_anomaly()`  [EXTRACTED]
  test_detectors.py → detectors/session_anomaly.py

## Import Cycles
- None detected.

## Communities (11 total, 0 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.23
Nodes (22): create_event(), Build a normalized event.      Every parser routes through this, so the top-leve, identify_event(), parse_auth_failure(), parse_connection_closed(), parse_failed_login(), parse_host(), parse_invalid_user() (+14 more)

### Community 1 - "Community 1"
Cohesion: 0.26
Nodes (10): detect_behavior(), detect_bruteforce(), detect_service_anomaly(), detect_session_anomaly(), generate_statistics(), build_events(), entity(), main() (+2 more)

### Community 2 - "Community 2"
Cohesion: 0.20
Nodes (10): Architecture decisions, Commits table, Day 3, Detection progress, Engineering progress, Implemented features, Lessons learned, Metrics (+2 more)

### Community 3 - "Community 3"
Cohesion: 0.07
Nodes (26): Apache / Nginx Parser, Authentication Parser, Behaviour Analysis, Completed, Docker Parser, Engineering, Linux Log Parser - Development Roadmap, Persistence Detection (+18 more)

### Community 5 - "Community 5"
Cohesion: 0.14
Nodes (14): Behaviour Analysis, Credential Compromise, Current Detections, Current Features, Detection Engine, Documentation, Homelab Log Parser (Linux), Objectives (+6 more)

### Community 6 - "Community 6"
Cohesion: 0.15
Nodes (10): Alerting, Author, Design Philosophy, Detectors, Graphify Support, Parsers, Roadmap, Status (+2 more)

### Community 7 - "Community 7"
Cohesion: 0.15
Nodes (12): Architecture decisions, Commits table, Current Status, Day 1, Detection progress, Engineering progress, Implemented features, Lessons learned (+4 more)

### Community 8 - "Community 8"
Cohesion: 0.20
Nodes (10): Alert Schema, Architecture — Homelab Log Parser (Linux), Current Architecture, Detector Philosophy, Event Schema, Future: Event Expiration, Future: Streaming Design, Parser Pipeline (+2 more)

### Community 9 - "Community 9"
Cohesion: 0.20
Nodes (10): Architecture decisions, Commits table, Day 2, Detection progress, Engineering progress, Implemented features, Lessons learned, Metrics (+2 more)

### Community 10 - "Community 10"
Cohesion: 0.22
Nodes (9): Current Assumptions, False Negatives, False Positives, Limitations, Parser Assumptions, Roadmap for Production Readiness, Security Considerations — Homelab Log Parser (Linux), Synthetic Datasets (+1 more)

## Knowledge Gaps
- **86 isolated node(s):** `Parser Pipeline`, `Current Architecture`, `Planned Architecture`, `Event Schema`, `Alert Schema` (+81 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Linux Log Parser Development Journal` connect `Community 7` to `Community 9`, `Community 2`?**
  _High betweenness centrality (0.232) - this node is a cross-community bridge._
- **Why does `Homelab Log Parser (Linux)` connect `Community 5` to `Community 6`?**
  _High betweenness centrality (0.111) - this node is a cross-community bridge._
- **Why does `Architecture — Homelab Log Parser (Linux)` connect `Community 8` to `Community 6`?**
  _High betweenness centrality (0.079) - this node is a cross-community bridge._
- **What connects `Build a normalized event.      Every parser routes through this, so the top-leve`, `Hostname sits directly after the timestamp:     `Jun 11 15:00:00 Sentinel sshd-s`, `Lines vary between `... for user X ...` and `... for X ...`.` to the rest of the system?**
  _94 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 3` be split into smaller, more focused modules?**
  _Cohesion score 0.07407407407407407 - nodes in this community are weakly interconnected._
- **Should `Community 5` be split into smaller, more focused modules?**
  _Cohesion score 0.14285714285714285 - nodes in this community are weakly interconnected._