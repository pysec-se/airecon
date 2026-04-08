# Changelog

## [v0.1.7-beta] - 2026-04-02

### Fixed
- fix(server): `/api/status` now reports `degraded` when Ollama health check explicitly returns false (sticky online fallback only for transient probe failures)
- fix(tui): restored status bar visibility by keeping status bar CSS in widget-local `StatusBar.DEFAULT_CSS`
- fix(version): align package export by re-exporting version from `airecon._version` in `airecon/__init__.py`
- fix(quality): resolve Ruff F401 for package `__version__` re-export

### Improved
- feat(mcp): expose and display `total_tools` for MCP servers to avoid misleading truncated counts
- feat(tui): `/mcp list <name>` now shows first 10 tools only to keep UI/context lightweight
- feat(tui): moved ConfirmDelete modal CSS to global `styles.tcss` with scoped selectors

### Validation
- tests: suite green at release time

---

## [v0.1.6-beta] - 2026-03-17

### Critical Security Fixes

#### Session Save Race Condition
- fix(agent): add `asyncio.Lock()` to `_schedule_token_usage_snapshot_save()` to prevent concurrent session save corruption
- fix(agent): acquire lock in `stop()` method before synchronous session save
- fix(server): call `agent.stop()` in lifespan shutdown to ensure session saved on exit

#### Symlink TOCTOU Vulnerability
- fix(filesystem): check `file_path.is_symlink()` before create/read operations
- fix(filesystem): resolve symlink and verify it points within workspace
- fix(filesystem): use atomic writes via `tempfile.mkstemp()` + `os.replace()` to prevent partial writes

#### Command Injection Prevention
- fix(validators): add 8 new dangerous patterns to `DANGEROUS_PATTERNS`:
  - `\$\{[^}]+\}` - variable expansion
  - `<\([^)]+\)` - process substitution
  - `\$'[^']*'` - ANSI-C quoting
  - `` `[^`]+` `` - backtick command substitution
  - `\$\([^)]+\)` - $(command) substitution
  - `;\s*(curl|wget|nc|...)` - pipe to interpreter
  - `\|\s*(bash|sh|python|...)` - pipe to interpreter
  - `/etc/(passwd|shadow|sudoers|ssh/)` - sensitive file access
  - `chmod\s+[0-7]*[4-7][0-7]{2}` - setuid/setgid chmod

### Stability Improvements

#### Session Persistence
- fix(agent): save session on Ctrl+C/exit in `AgentLoop.stop()` method
- fix(server): call `agent.stop()` in lifespan shutdown handler
- fix(agent): log session data count (subdomains, live_hosts, vulns) on save

#### HTTP Timeout Protection
- fix(fuzzer): propagate baseline failures with explicit logging
- fix(fuzzer): skip unreachable params (status=-1) before fuzzing
- fix(fuzzer): log skipped params due to baseline failures

#### Browser Resource Cleanup
- fix(browser): add force kill fallback (`pkill -9 chromium`) on cleanup failure
- fix(browser): surface screenshot failures to caller via `screenshot_failure` flag in result dict

#### CVE Validation
- fix(reporting): tighten `_CVE_RE` regex from `r'^CVE-\d{4}-\d{4,7}$'` to `r'^CVE-(19[89]|20\d{2})-\d{4,7}$'`
- fix(reporting): validate CVE year range 1989-2099 to prevent fake CVEs

#### Context Management
- fix(models): make context limits config-based via `_get_context_limits()`
- fix(models): calculate `max_conversation_messages = ollama_num_ctx // 128`
- fix(models): add 5 new config keys: `agent_max_conversation_messages`, `agent_compression_trigger_ratio`,
  `agent_uncompressed_keep_count`, `agent_llm_compression_num_ctx`, `agent_llm_compression_num_predict`

#### Tool Result Truncation
- fix(models): add `_truncate_tool_result()` helper function (50KB limit)
- fix(executors): add `_append_tool_history()` helper with truncation on append
- fix(models): keep legacy truncation in `add_message()` as safety net

#### Incremental Pruning
- fix(loop): change `_executed_cmd_hashes` pruning from `.clear()` to FIFO keep newest 2500
- fix(loop): log pruning: "incrementally pruned: X → 2500 entries"

### Code Quality
- refactor: remove 51 lines of verbose FIX comments
- refactor: simplify docstrings across 12 files
- test: update test_validation.py to reflect improved security
- test: all 1369 tests passing (100% backward compatible)

### Files Modified
- `airecon/proxy/agent/loop.py` - Session lock, save on shutdown, incremental pruning
- `airecon/proxy/agent/validators.py` - 8 new dangerous patterns
- `airecon/proxy/agent/models.py` - Config-based context limits, truncation helper
- `airecon/proxy/agent/session.py` - Vulnerability dedup fix
- `airecon/proxy/agent/executors.py` - Tool result truncation helper
- `airecon/proxy/filesystem.py` - Symlink TOCTOU protection, atomic writes
- `airecon/proxy/browser.py` - Screenshot failure surfacing, force kill cleanup
- `airecon/proxy/fuzzer.py` - Baseline failure propagation
- `airecon/proxy/reporting.py` - CVE validation regex
- `airecon/proxy/server.py` - Session save on shutdown
- `airecon/proxy/config.py` - Bounds validation for all numeric fields
- `tests/proxy/test_validation.py` - Updated for improved security
- `tests/proxy/test_fuzzer.py` - Updated for baseline failure handling

---

### Added

#### Phase 1 — Autonomous Recovery & Exploration Engine
- feat(agent): watchdog forcing — LLM stuck in text-only loop forces `execute` tool (max 2x before abort)
- feat(agent): anti-stagnation exploration — temperature boost when no new high-confidence evidence (≥0.65)
- feat(agent): tool diversity tracking — same-tool streak detection via `_recent_tool_names` deque
- feat(agent): per-phase exploration directives via `_build_exploration_directive()`
- feat(agent): quality scoreboard — evidence 40%, reproducibility 35%, impact 25%
- feat(agent): recovery state context injected after conversation truncation
- feat(models): `objective_queue` (max 64) + `evidence_log` (max 200, dedup last 50)
- feat(config): 6 new exploration config keys (`agent_exploration_mode`, `agent_exploration_intensity`,
  `agent_exploration_temperature`, `agent_stagnation_threshold`, `agent_tool_diversity_window`,
  `agent_max_same_tool_streak`)

#### Phase 2 — Skill Orchestration & Tool Budget
- feat(agent): skill phase boost — `_PHASE_SKILL_DIRECTORIES` gives +2 score to phase-preferred skills
- feat(agent): tool budget per phase — `_PHASE_TOOL_BUDGETS` with soft limits per tool per phase
- feat(agent): budget warnings at 75% (warning), 100% (exhausted), 0 (discouraged)
- feat(pipeline): phase skill hints injected into `get_phase_prompt()`

#### Ollama Stability — Context & VRAM Recovery
- feat(agent): multi-level VRAM crash recovery — 4 escalation tiers persisted via `_adaptive_num_ctx`:
  Tier 1 (`ollama_num_ctx_small`, 80 msgs), Tier 2 (÷2, 50 msgs, 5s wait),
  Tier 3 (÷4, 30 msgs, 10s wait), Tier 4 (4096, 20 msgs, 30s wait)
- feat(agent): proactive context monitoring — trims at ≥80% token usage, aggressive at ≥90%
- feat(agent): dynamic compression interval (5/10/15 iters based on context fullness)
- feat(agent): skip `compress_with_llm` when >65% context full (OOM prevention)
- feat(agent): `_cap_tool_result` scales down dynamically with `_adaptive_num_ctx`
- feat(agent): `_adaptive_num_predict_cap` limits token generation after VRAM crash
- feat(ollama): `complete()` accepts `options: dict` (num_ctx, num_predict, temperature)
- feat(models): `compress_with_llm` passes `num_ctx=8192, num_predict=1024` to avoid OOM
- feat(agent): session auto-saved after each VRAM crash recovery

#### Tested Endpoints Memory
- feat(session): `SessionData.tested_endpoints` — LRU list (max 500) tracking `"METHOD url"` strings
- feat(session): `record_tested_endpoint(session, url, method)` with dedup + LRU eviction
- feat(agent): `_record_tested_endpoint()` auto-records from execute (curl), browser_action, fuzz tools
- feat(agent): last 20 tested endpoints shown in `_build_critical_findings_context` after truncation

#### @/file and @/folder References
- feat(agent): `@/path` resolver — copies local files/dirs to Docker workspace/uploads/ automatically
- feat(agent): per-file `try/except OSError` in directory copy — single file errors no longer abort
- feat(agent): detailed skip reporting (binary, too-large, OS-error) in copy summary

#### TUI — Slash Command Autocomplete
- feat(tui): `/` prefix triggers slash command autocomplete in chat input
- feat(tui): `PathCompleter` widget with proper error logging

#### Agent Intelligence
- feat(agent): attack chain detection — links vuln evidence across phases
- feat(agent): semantic dedup for objectives (Jaccard 0.70 threshold)
- feat(agent): adaptive thinking with confidence floor 0.65 for meaningful evidence
- feat(agent): cross-session memory — loads prior session findings on start
- feat(agent): 6 hypothesis-driven vuln discovery improvements
- feat(data): expand all correlation pattern files (major expansion)
- feat(data): rename `expert_testing_patterns.json` → `patterns.json`
- feat(zeroday): redesign zero-day patterns for realistic LLM discovery
- feat(agent): smart fuzzer routing + dynamic URL correlation + injection-chain detection
- feat(agent): data-driven injection points, port/tech hints, HTTP impact validation
- feat(skills): add 22 new skills (frameworks, protocols, technologies, LLM coverage)
- feat(skills): aggressive exploration mode + headless reverse/pwn skill loading

### Fixed
- fix(agent): `[CONTEXT MONITOR]` messages removed from TUI output (logged to file only)
- fix(security): block `$()` and backtick command substitution in watchdog (`has_dangerous_patterns()`)
- fix(security): auth header propagation improvements
- fix(validators): add auth browser actions: `login_form`, `handle_totp`, `save_auth_state`,
  `inject_cookies`, `oauth_authorize`
- fix(agent): `_executed_cmd_hashes` pruned at >5000 entries to prevent memory leak
- fix(agent): IDOR false positive reduction in correlation engine
- fix(agent): phase timeout now counts iterations (not wall-clock time)
- fix(agent): evidence truncation preserves high-confidence items
- fix(agent): press_key dedup, DDG lock race, port-scan rerun block
- fix(agent): harden LLM loop, subagent isolation, and command detection
- fix(agent): subdomain workspace path, CTF false positives, LLM hallucination
- fix(agent): watchdog extracts full multi-line bash scripts (not just first command)
- fix(ollama): enforce thinking/native_tools invariant + guard max_retries
- fix(ollama): improve detection-failure warning
- fix(browser): add `--ignore-certificate-errors` for TLS cipher mismatch on pentest targets
- fix(docker): fix 8+ binary name mismatches between tools_meta.json and installed binaries
- fix(docker): fix race condition in docker force_stop
- fix(patterns): fix all match-breaking issues across data pattern files
- fix(reporting): `_resolve_report_workspace_target()` for URL/file/path resolution
- fix(tui): `PathCompleter.hide()` bare except replaced with proper logging
- fix(data): `spawn_agent` max iterations 200→100 in tools.json
- fix(data): `web_search` updated to SearXNG preferred + DuckDuckGo fallback

### Changed
- refactor(ollama): remove name-heuristic capability detection
- docs: condense README from 983 → 228 lines
- docs: add airecon-skills community library reference
- ci: add label-based project board routing workflow
- chore: add `coming_soon/` to .gitignore (local-only roadmap)
- style: fix ruff E702 semicolons, unused imports, unused variables across codebase
- test: 448 → 879 tests (96% growth); new test files for context recovery, tested endpoints,
  recon dedup, path completer, command parse, reporting helpers

---

## [v0.1.5-beta] - 2026-03-05

### Fixed
- fix(core): unpack tuple return value from auto_load_skills_for_message to resolve unhashable list crash
- fix(core): resolve correlation logger, fuzzer graceful degradation, and browser timeout bugs
- fix(docker): fix race condition in docker force_stop and ollama model detection
- fix(tui): initialize live output and remove unused reload override
- fix(test): patch browser unpacking bug in unit tests

### Added
- test: implement comprehensive unit test suite covering proxy, agent, and TUI components

### Changed
- chore: remove .vscode from version control tracking
- chore: add __pycache__ and workspace/ to .gitignore
- docs: update README badge version formats

---
