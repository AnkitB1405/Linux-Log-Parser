# Graph Report - Log_Parser  (2026-08-24)

## Corpus Check
- 24 files · ~23,274 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 225 nodes · 294 edges · 13 communities
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS · INFERRED: 1 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `dc8a36d3`
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
3. `Day 6` - 11 edges
4. `Architecture — Homelab Log Parser (Linux)` - 10 edges
5. `Day 1` - 10 edges
6. `Day 2` - 10 edges
7. `Day 3` - 10 edges
8. `Security Considerations — Homelab Log Parser (Linux)` - 9 edges
9. `identify_event()` - 8 edges
10. `identify_event()` - 8 edges

## Surprising Connections (you probably didn't know these)
- `check_docker()` --calls--> `identify_event()`  [EXTRACTED]
  test_detectors.py → parser/docker_parser.py
- `build_events()` --calls--> `identify_event()`  [EXTRACTED]
  test_detectors.py → parser/ssh_parser.py
- `check_docker()` --calls--> `detect_container_anomaly()`  [EXTRACTED]
  test_detectors.py → detectors/container_anomaly.py
- `check_docker()` --calls--> `detect_container_escape()`  [EXTRACTED]
  test_detectors.py → detectors/container_escape.py
- `check_escape_assessment()` --calls--> `assess()`  [EXTRACTED]
  test_detectors.py → detectors/container_escape.py

## Import Cycles
- None detected.

## Communities (13 total, 0 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.18
Nodes (11): Architecture decisions, Bugs fixed, Commits table, Day 5, Detection progress, Engineering progress, Implemented features, Lessons learned (+3 more)

### Community 1 - "Community 1"
Cohesion: 0.09
Nodes (32): detect_auth_anomaly(), count_bursts(), detect_behavior(), How many windows starting at an entry hold at least BURST attempts.      ponytai, First band whose threshold is met. (None, None) below the lowest., severity_for(), detect_bruteforce(), detect_container_anomaly() (+24 more)

### Community 2 - "Community 2"
Cohesion: 0.09
Nodes (22): Architecture decisions, Architecture decisions, Commits table, Commits table, Current Status, Day 2, Day 3, Detection progress (+14 more)

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
Cohesion: 0.20
Nodes (10): Architecture decisions, Commits table, Day 1, Detection progress, Engineering progress, Implemented features, Lessons learned, Metrics (+2 more)

### Community 8 - "Community 8"
Cohesion: 0.14
Nodes (11): Alert Schema, Architecture — Homelab Log Parser (Linux), Current Architecture, Detector Philosophy, Event Schema, Future: Event Expiration, Future: Streaming Design, Parser Pipeline (+3 more)

### Community 9 - "Community 9"
Cohesion: 0.09
Nodes (29): collect_events(), (label, lines, parser) for every log this run should read.      `--live` swaps t, Parse every source into one normalized event list., sources(), generate_statistics(), identify_event(), parse_action(), parse_timestamp() (+21 more)

### Community 10 - "Community 10"
Cohesion: 0.20
Nodes (10): Current Assumptions, Deployment context, False Negatives, False Positives, Limitations, Parser Assumptions, Roadmap for Production Readiness, Security Considerations — Homelab Log Parser (Linux) (+2 more)

### Community 11 - "Community 11"
Cohesion: 0.18
Nodes (11): Architecture decisions, Bugs fixed, Commits table, Day 6, Detection progress, Engineering progress, Implemented features, Lessons learned (+3 more)

### Community 12 - "Community 12"
Cohesion: 0.18
Nodes (11): Architecture decisions, Bugs fixed, Commits table, Day 4, Detection progress, Engineering progress, Implemented features, Lessons learned (+3 more)

## Knowledge Gaps
- **119 isolated node(s):** `Parser Pipeline`, `Current Architecture`, `Planned Architecture`, `Event Schema`, `Alert Schema` (+114 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Linux Log Parser Development Journal` connect `Community 2` to `Community 0`, `Community 11`, `Community 12`, `Community 7`?**
  _High betweenness centrality (0.269) - this node is a cross-community bridge._
- **Why does `Homelab Log Parser (Linux)` connect `Community 5` to `Community 8`?**
  _High betweenness centrality (0.079) - this node is a cross-community bridge._
- **Why does `Day 4` connect `Community 12` to `Community 2`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **What connects `How many windows starting at an entry hold at least BURST attempts.      ponytai`, `First band whose threshold is met. (None, None) below the lowest.`, ``docker exec` into a running container is the container equivalent of an SSH log` to the rest of the system?**
  _147 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.09146341463414634 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.08695652173913043 - nodes in this community are weakly interconnected._
- **Should `Community 3` be split into smaller, more focused modules?**
  _Cohesion score 0.07407407407407407 - nodes in this community are weakly interconnected._