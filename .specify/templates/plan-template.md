# Implementation Plan: [FEATURE]

**Branch**: `[###-feature-name]` | **Date**: [DATE] | **Spec**: [link]
**Input**: Feature specification from `/specs/[###-feature-name]/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/commands/plan.md` for the execution workflow.

## Summary

[Extract from feature spec: primary requirement + technical approach from research]

## Technical Context

<!--
  ACTION REQUIRED: Replace the content in this section with the technical details
  for the project. The structure here is presented in advisory capacity to guide
  the iteration process.
-->

**Language/Version**: [e.g., Python 3.11, Swift 5.9, Rust 1.75 or NEEDS CLARIFICATION]  
**Primary Dependencies**: [e.g., FastAPI, UIKit, LLVM or NEEDS CLARIFICATION]  
**Storage**: [if applicable, e.g., PostgreSQL, CoreData, files or N/A]  
**Testing**: [e.g., pytest, XCTest, cargo test or NEEDS CLARIFICATION]  
**Target Platform**: [e.g., Linux server, iOS 15+, WASM or NEEDS CLARIFICATION]
**Project Type**: [single/web/mobile - determines source structure]  
**Performance Goals**: [domain-specific, e.g., 1000 req/s, 10k lines/sec, 60 fps or NEEDS CLARIFICATION]  
**Constraints**: [domain-specific, e.g., <200ms p95, <100MB memory, offline-capable or NEEDS CLARIFICATION]  
**Scale/Scope**: [domain-specific, e.g., 10k users, 1M LOC, 50 screens or NEEDS CLARIFICATION]

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**I. Go Concurrency Idioms**
- [ ] Connection handling uses dedicated goroutines with proper cleanup
- [ ] Inter-goroutine communication uses channels (not shared memory + locks)
- [ ] Context cancellation propagates through goroutine hierarchies
- [ ] Worker pools are used for CPU-bound operations (if applicable)

**II. Rigorous Error Handling**
- [ ] All network operations check errors explicitly
- [ ] Errors are wrapped with context (`fmt.Errorf` with `%w`)
- [ ] Transient vs permanent errors are distinguished
- [ ] Cleanup is guaranteed via `defer` statements
- [ ] Public API error conditions are documented

**III. Secure TLS Interception** *(if feature involves TLS)*
- [ ] Certificate generation uses `crypto/rand`
- [ ] Private keys meet minimum strength requirements (2048-bit RSA / P-256 ECDSA)
- [ ] Certificate operations are logged with fingerprints
- [ ] Certificate caching has bounds (time + memory limits)
- [ ] TLS validation checks hostname, expiration, chain of trust
- [ ] TLS version requirements are met (TLS 1.2 min, 1.3 preferred)

**IV. Performance & Efficiency** *(if feature is performance-critical)*
- [ ] Latency impact measured and within budget (<5ms p99 overhead)
- [ ] Hot paths minimize allocations (buffer pools, zero-copy)
- [ ] Benchmarks exist for critical operations
- [ ] pprof endpoints available for profiling

**V. Simplicity & Maintainability**
- [ ] Code prioritizes readability over cleverness
- [ ] Abstractions solve concrete problems (YAGNI applied)
- [ ] Dependencies are justified (prefer stdlib)
- [ ] Public APIs are minimal and hard to misuse
- [ ] Magic numbers are named constants with explanatory comments
- [ ] Protocol logic references specifications (RFC numbers)

## Project Structure

### Documentation (this feature)

```text
specs/[###-feature]/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)
<!--
  ACTION REQUIRED: Replace the placeholder tree below with the concrete layout
  for this feature. Delete unused options and expand the chosen structure with
  real paths (e.g., apps/admin, packages/something). The delivered plan must
  not include Option labels.
-->

```text
# [REMOVE IF UNUSED] Option 1: Single project (DEFAULT)
src/
├── models/
├── services/
├── cli/
└── lib/

tests/
├── contract/
├── integration/
└── unit/

# [REMOVE IF UNUSED] Option 2: Web application (when "frontend" + "backend" detected)
backend/
├── src/
│   ├── models/
│   ├── services/
│   └── api/
└── tests/

frontend/
├── src/
│   ├── components/
│   ├── pages/
│   └── services/
└── tests/

# [REMOVE IF UNUSED] Option 3: Mobile + API (when "iOS/Android" detected)
api/
└── [same as backend above]

ios/ or android/
└── [platform-specific structure: feature modules, UI flows, platform tests]
```

**Structure Decision**: [Document the selected structure and reference the real
directories captured above]

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |
