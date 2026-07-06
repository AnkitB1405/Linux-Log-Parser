# Graph Report - Log_Parser  (2026-07-06)

## Corpus Check
- 9 files · ~4,083 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 73 nodes · 93 edges · 9 communities
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `ae4b7a87`
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

## God Nodes (most connected - your core abstractions)
1. `identify_event()` - 12 edges
2. `parse_timestamp()` - 10 edges
3. `Homelab Log Parser (Linux)` - 7 edges
4. `Roadmap` - 6 edges
5. `Phase 2 — Additional Parsers` - 5 edges
6. `parse_failed_login()` - 4 edges
7. `parse_successful_login()` - 4 edges
8. `V1` - 4 edges
9. `Phase 1 — SSH Monitoring Engine 🔄` - 4 edges
10. `Phase 3 — Detection Expansion` - 4 edges

## Surprising Connections (you probably didn't know these)
- None detected - all connections are within the same source files.

## Import Cycles
- None detected.

## Communities (9 total, 0 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.30
Nodes (14): identify_event(), parse_auth_failure(), parse_connection_closed(), parse_failed_login(), parse_invalid_user(), parse_multiple_failures(), parse_service_started(), parse_service_stopped() (+6 more)

### Community 1 - "Community 1"
Cohesion: 0.33
Nodes (4): detect_behavior(), detect_bruteforce(), detect_service_anomaly(), detect_session_anomaly()

### Community 3 - "Community 3"
Cohesion: 0.14
Nodes (13): Completed, Linux Log Parser - Development Roadmap, Phase 0 — Architecture & Planning ✅, Phase 10 — AI Layer (V2), Phase 4 — Event Normalization, Phase 5 — Outputs, Phase 6 — Graphify Integration, Phase 7 — Dashboard (+5 more)

### Community 4 - "Community 4"
Cohesion: 0.40
Nodes (5): Apache / Nginx Parser, Authentication Parser, Docker Parser, Phase 2 — Additional Parsers, Syslog Parser

### Community 5 - "Community 5"
Cohesion: 0.22
Nodes (9): Current Features, Detection Engine, Documentation, Homelab Log Parser (Linux), Objectives, Project Structure, SSH Brute Force, SSH Parser (+1 more)

### Community 6 - "Community 6"
Cohesion: 0.18
Nodes (10): Alerting, Author, Design Philosophy, Detectors, Graphify Support, Parsers, Roadmap, Status (+2 more)

### Community 7 - "Community 7"
Cohesion: 0.50
Nodes (4): Behaviour Analysis, Persistence Detection, Phase 3 — Detection Expansion, Service Instability

### Community 8 - "Community 8"
Cohesion: 0.50
Nodes (4): Engineering, Phase 1 — SSH Monitoring Engine 🔄, SSH Detection Engine, SSH Parser

## Knowledge Gaps
- **36 isolated node(s):** `Objectives`, `Documentation`, `SSH Parser`, `SSH Brute Force`, `Project Structure` (+31 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Homelab Log Parser (Linux)` connect `Community 5` to `Community 6`?**
  _High betweenness centrality (0.129) - this node is a cross-community bridge._
- **Why does `Phase 2 — Additional Parsers` connect `Community 4` to `Community 3`?**
  _High betweenness centrality (0.068) - this node is a cross-community bridge._
- **What connects `Extract username and source IP     from a failed SSH login event.`, `Extract username and source IP     from a successful SSH login event.`, `Identify the SSH event type from a log line.` to the rest of the system?**
  _39 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 3` be split into smaller, more focused modules?**
  _Cohesion score 0.14285714285714285 - nodes in this community are weakly interconnected._