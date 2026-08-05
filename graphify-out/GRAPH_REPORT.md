# Graph Report - Log_Parser  (2026-08-05)

## Corpus Check
- 17 files · ~8,653 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 129 nodes · 150 edges · 11 communities
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `a6fcd441`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]

## God Nodes (most connected - your core abstractions)
1. `identify_event()` - 12 edges
2. `parse_timestamp()` - 10 edges
3. `Architecture — Homelab Log Parser (Linux)` - 10 edges
4. `Day 1` - 10 edges
5. `Day 2` - 10 edges
6. `Security Considerations — Homelab Log Parser (Linux)` - 9 edges
7. `Homelab Log Parser (Linux)` - 7 edges
8. `Detection Engine` - 7 edges
9. `Roadmap` - 6 edges
10. `Phase 2 — Additional Parsers` - 5 edges

## Surprising Connections (you probably didn't know these)
- None detected - all connections are within the same source files.

## Import Cycles
- None detected.

## Communities (11 total, 0 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.30
Nodes (14): identify_event(), parse_auth_failure(), parse_connection_closed(), parse_failed_login(), parse_invalid_user(), parse_multiple_failures(), parse_service_started(), parse_service_stopped() (+6 more)

### Community 1 - "Community 1"
Cohesion: 0.17
Nodes (5): detect_behavior(), detect_bruteforce(), detect_service_anomaly(), detect_session_anomaly(), generate_statistics()

### Community 3 - "Community 3"
Cohesion: 0.09
Nodes (21): Behaviour Analysis, Completed, Engineering, Linux Log Parser - Development Roadmap, Persistence Detection, Phase 0 — Architecture & Planning ✅, Phase 10 — AI Layer (V2), Phase 1 — SSH Monitoring Engine 🔄 (+13 more)

### Community 4 - "Community 4"
Cohesion: 0.40
Nodes (5): Apache / Nginx Parser, Authentication Parser, Docker Parser, Phase 2 — Additional Parsers, Syslog Parser

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
- **77 isolated node(s):** `Parser Pipeline`, `Current Architecture`, `Planned Architecture`, `Event Schema`, `Alert Schema` (+72 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Linux Log Parser Development Journal` connect `Community 7` to `Community 9`?**
  _High betweenness centrality (0.206) - this node is a cross-community bridge._
- **Why does `Homelab Log Parser (Linux)` connect `Community 5` to `Community 6`?**
  _High betweenness centrality (0.138) - this node is a cross-community bridge._
- **Why does `Architecture — Homelab Log Parser (Linux)` connect `Community 8` to `Community 6`?**
  _High betweenness centrality (0.100) - this node is a cross-community bridge._
- **What connects `Extract username and source IP     from a failed SSH login event.`, `Extract username and source IP     from a successful SSH login event.`, `Identify the SSH event type from a log line.` to the rest of the system?**
  _80 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 3` be split into smaller, more focused modules?**
  _Cohesion score 0.09090909090909091 - nodes in this community are weakly interconnected._
- **Should `Community 5` be split into smaller, more focused modules?**
  _Cohesion score 0.14285714285714285 - nodes in this community are weakly interconnected._