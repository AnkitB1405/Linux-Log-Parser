# Graph Report - Log_Parser  (2026-08-21)

## Corpus Check
- 19 files · ~16,661 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 172 nodes · 198 edges · 13 communities
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `35dce822`
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
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]

## God Nodes (most connected - your core abstractions)
1. `Day 4` - 11 edges
2. `Day 5` - 11 edges
3. `Architecture — Homelab Log Parser (Linux)` - 10 edges
4. `Day 1` - 10 edges
5. `Day 2` - 10 edges
6. `Day 3` - 10 edges
7. `Security Considerations — Homelab Log Parser (Linux)` - 9 edges
8. `Homelab Log Parser (Linux)` - 8 edges
9. `Detection Engine` - 8 edges
10. `identify_event()` - 7 edges

## Surprising Connections (you probably didn't know these)
- `run_detectors()` --calls--> `detect_behavior()`  [EXTRACTED]
  test_detectors.py → detectors/behavior.py
- `run_detectors()` --calls--> `detect_bruteforce()`  [EXTRACTED]
  test_detectors.py → detectors/bruteforce.py
- `run_detectors()` --calls--> `detect_service_anomaly()`  [EXTRACTED]
  test_detectors.py → detectors/service_anomaly.py
- `run_detectors()` --calls--> `detect_session_anomaly()`  [EXTRACTED]
  test_detectors.py → detectors/session_anomaly.py
- `build_events()` --calls--> `identify_event()`  [EXTRACTED]
  test_detectors.py → parser/ssh_parser.py

## Import Cycles
- None detected.

## Communities (13 total, 0 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.18
Nodes (11): Architecture decisions, Bugs fixed, Commits table, Day 5, Detection progress, Engineering progress, Implemented features, Lessons learned (+3 more)

### Community 1 - "Community 1"
Cohesion: 0.18
Nodes (15): detect_behavior(), detect_bruteforce(), detect_service_anomaly(), detect_session_anomaly(), generate_statistics(), create_event(), Build a normalized event.      Every parser routes through this, so the top-leve, identify_event() (+7 more)

### Community 2 - "Community 2"
Cohesion: 0.20
Nodes (10): Architecture decisions, Commits table, Day 3, Detection progress, Engineering progress, Implemented features, Lessons learned, Metrics (+2 more)

### Community 3 - "Community 3"
Cohesion: 0.07
Nodes (26): Apache / Nginx Parser, Authentication Parser, Behaviour Analysis, Completed, Docker Parser, Engineering, Linux Log Parser - Development Roadmap, Persistence Detection (+18 more)

### Community 5 - "Community 5"
Cohesion: 0.12
Nodes (16): Alert Format, Behaviour Analysis, Credential Compromise, Current Detections, Current Features, Detection Engine, Documentation, Homelab Log Parser (Linux) (+8 more)

### Community 6 - "Community 6"
Cohesion: 0.20
Nodes (10): AI Assistance, Alerting, Author, Design Philosophy, Detectors, Parsers, Roadmap, Status (+2 more)

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
Cohesion: 0.15
Nodes (10): Graphify Support, Current Assumptions, False Negatives, False Positives, Limitations, Parser Assumptions, Roadmap for Production Readiness, Security Considerations — Homelab Log Parser (Linux) (+2 more)

### Community 11 - "Community 11"
Cohesion: 0.21
Nodes (6): checks(), identify(), Regex lab — learn `re` on this project's own log lines.  Not part of the pipelin, First pattern that matches wins. Returns (event_type, fields) or None., section_6_table(), section_8_exercises()

### Community 12 - "Community 12"
Cohesion: 0.18
Nodes (11): Architecture decisions, Bugs fixed, Commits table, Day 4, Detection progress, Engineering progress, Implemented features, Lessons learned (+3 more)

## Knowledge Gaps
- **109 isolated node(s):** `Parser Pipeline`, `Current Architecture`, `Planned Architecture`, `Event Schema`, `Alert Schema` (+104 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Linux Log Parser Development Journal` connect `Community 7` to `Community 0`, `Community 9`, `Community 2`, `Community 12`?**
  _High betweenness centrality (0.359) - this node is a cross-community bridge._
- **Why does `Homelab Log Parser (Linux)` connect `Community 5` to `Community 10`?**
  _High betweenness centrality (0.124) - this node is a cross-community bridge._
- **Why does `Day 4` connect `Community 12` to `Community 7`?**
  _High betweenness centrality (0.086) - this node is a cross-community bridge._
- **What connects `Build a normalized event.      Every parser routes through this, so the top-leve`, `Parse one syslog line into a normalized event, or None if no pattern     claims`, `Regex lab — learn `re` on this project's own log lines.  Not part of the pipelin` to the rest of the system?**
  _114 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 3` be split into smaller, more focused modules?**
  _Cohesion score 0.07407407407407407 - nodes in this community are weakly interconnected._
- **Should `Community 5` be split into smaller, more focused modules?**
  _Cohesion score 0.125 - nodes in this community are weakly interconnected._