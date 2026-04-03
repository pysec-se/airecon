from __future__ import annotations

import asyncio
import logging
import time

from .session import SessionData, save_session

logger = logging.getLogger("airecon.agent")


def _estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return len(text) // 3


class _StateMixin:
    def _sync_token_usage_from_session(self) -> None:
        if not self._session:
            return
        usage = self.state.token_usage
        usage["cumulative"] = int(getattr(self._session, "token_total", 0) or 0)
        usage["cumulative_prompt"] = int(
            getattr(self._session, "token_prompt_total", 0) or 0
        )
        usage["cumulative_completion"] = int(
            getattr(self._session, "token_completion_total", 0) or 0
        )
        # FIX: Preserve budget usage instead of resetting to 0
        # This ensures context pressure tracking persists across restarts
        session_budget_used = getattr(self._session, "token_last_used", 0) or 0
        usage["used"] = session_budget_used
        usage["last_prompt"] = 0
        usage["last_completion"] = 0
        logger.debug(
            "Session resumed with token usage: cumulative=%d, budget_used=%d",
            usage["cumulative"], session_budget_used
        )

    def _sync_token_usage_to_session(self) -> None:
        if not self._session:
            return
        usage = self.state.token_usage
        self._session.token_total = int(usage.get("cumulative", 0) or 0)
        self._session.token_prompt_total = int(
            usage.get("cumulative_prompt", 0) or 0
        )
        self._session.token_completion_total = int(
            usage.get("cumulative_completion", 0) or 0
        )
        self._session.token_last_used = int(usage.get("used", 0) or 0)
        self._sync_recovery_state_to_session()

    def _sync_conversation_to_session(self) -> None:
        if not self._session:
            return

        if hasattr(self.state, 'conversation') and self.state.conversation:
            self._session.conversation = list(self.state.conversation)[-1000:]

    def _save_to_memory_realtime(self) -> None:
        if not self._session or not self._session.target:
            return

        has_valid_subdomains = (
            len(self._session.subdomains) >= 1 and
            any('.' in str(sub) for sub in self._session.subdomains)
        )
        has_valid_hosts = len(self._session.live_hosts) > 0
        has_valid_vulns = (
            len(self._session.vulnerabilities) > 0 and
            any(v.get('severity') for v in self._session.vulnerabilities)
        )

        if not (has_valid_subdomains or has_valid_hosts or has_valid_vulns):
            logger.debug(
                "Skipping memory save - no valid data yet (subs=%d, hosts=%d, vulns=%d)",
                len(self._session.subdomains),
                len(self._session.live_hosts),
                len(self._session.vulnerabilities)
            )
            return

        if self._memory_manager is None:
            try:
                from ..memory import get_memory_manager
                self._memory_manager = get_memory_manager()
            except Exception as e:
                logger.debug("Memory manager init failed: %s", e)
                return

        if not self._memory_manager:
            return

        try:

            valid_subdomains = [
                str(sub).strip().lower()
                for sub in self._session.subdomains
                if sub and '.' in str(sub) and len(str(sub)) <= 253
            ][:1000]

            valid_live_hosts = [
                str(host).strip()
                for host in self._session.live_hosts
                if host and (str(host).startswith('http://') or str(host).startswith('https://'))
            ][:500]

            valid_vulnerabilities = [
                {
                    'type': v.get('type', 'vulnerability'),
                    'severity': v.get('severity', 'Medium'),
                    'url': v.get('url', ''),
                    'description': v.get('description', '')[:500],
                    'evidence': v.get('evidence', [])[:10],
                }
                for v in self._session.vulnerabilities
                if v.get('severity') or v.get('description')
            ][:100]

            self._memory_manager.save_session({
                "session_id": self._session.session_id,
                "target": self._session.target,
                "current_phase": self._session.current_phase,
                "subdomains": valid_subdomains,
                "live_hosts": valid_live_hosts,
                "vulnerabilities": valid_vulnerabilities,
                "token_total": self._session.token_total,
                "model_used": self.ollama.model if hasattr(self, 'ollama') else None,
            })

            if valid_subdomains or self._session.open_ports or self._session.technologies:

                valid_ports = {
                    str(port): service
                    for port, service in self._session.open_ports.items()
                    if str(port).isdigit() and 1 <= int(port) <= 65535
                }

                valid_techs = {
                    str(name).strip(): str(version).strip()
                    for name, version in self._session.technologies.items()
                    if name and version
                }

                self._memory_manager.save_target_intel({
                    "target": self._session.target,
                    "subdomains": valid_subdomains,
                    "ports": valid_ports,
                    "technologies": valid_techs,
                    "waf": self._session.waf_profiles.get(self._session.target, {}).get('waf_name') if self._session.waf_profiles else None,
                })

            logger.info(
                "✓ Real-time memory save: %d subdomains, %d live hosts, %d vulns, %d ports, %d techs",
                len(valid_subdomains),
                len(valid_live_hosts),
                len(valid_vulnerabilities),
                len(valid_ports) if 'valid_ports' in locals() else 0,
                len(valid_techs) if 'valid_techs' in locals() else 0
            )
        except Exception as e:
            logger.debug("Real-time memory save failed: %s", e)

    def _save_recon_exploit_pattern(
        self,
        technique_name: str,
        pattern_type: str,
        commands: list[str],
        success: bool,
        target_tech: str | None = None,
        description: str = "",
        effectiveness_score: float | None = None,
    ) -> None:
        if not self._session or not self._memory_manager:
            return

        if not hasattr(self._session, '_technique_stats'):
            self._session._technique_stats = {}

        key = f"{technique_name}:{target_tech or 'generic'}"
        if key not in self._session._technique_stats:
            self._session._technique_stats[key] = {
                'technique_name': technique_name,
                'pattern_type': pattern_type,
                'commands': commands,
                'times_used': 0,
                'times_successful': 0,
                'target_tech': target_tech,
                'description': description,
            }

        stats = self._session._technique_stats[key]
        stats['times_used'] += 1
        if success:
            stats['times_successful'] += 1

        success_rate = stats['times_successful'] / max(stats['times_used'], 1)

        if success_rate >= 0.70 and stats['times_used'] >= 3:
            if effectiveness_score is None:
                effectiveness_score = success_rate * 100

            self._memory_manager.save_pattern({
                'type': pattern_type,
                'tech': target_tech,
                'technique_name': technique_name,
                'description': description or f"Effective {pattern_type} technique for {target_tech or 'general targets'}",
                'success_rate': success_rate,
                'times_used': stats['times_used'],
                'commands_used': commands,
                'effectiveness_score': effectiveness_score,
                'source_session': self._session.session_id,
            })

    def _sync_recovery_state_from_session(self) -> None:
        if not self._session:
            return
        sess_ctx = int(getattr(self._session, "adaptive_num_ctx", 0) or 0)
        sess_cap = int(getattr(self._session, "adaptive_num_predict_cap", 0) or 0)
        sess_crashes = int(getattr(self._session, "vram_crash_count", 0) or 0)

        if sess_ctx > 0:
            if self._adaptive_num_ctx > 0:
                self._adaptive_num_ctx = min(self._adaptive_num_ctx, sess_ctx)
            else:
                self._adaptive_num_ctx = sess_ctx

        if sess_cap > 0:
            self._adaptive_num_predict_cap = sess_cap

        if self._adaptive_num_ctx > 0 and self._adaptive_num_predict_cap > 0:
            self._adaptive_num_predict_cap = min(
                self._adaptive_num_predict_cap,
                max(512, self._adaptive_num_ctx // 4),
            )

        self._vram_crash_count = max(self._vram_crash_count, sess_crashes)

    def _sync_recovery_state_to_session(self) -> None:
        if not self._session:
            return
        self._session.adaptive_num_ctx = max(0, int(self._adaptive_num_ctx or 0))
        self._session.adaptive_num_predict_cap = max(
            0, int(self._adaptive_num_predict_cap or 0)
        )
        self._session.vram_crash_count = max(0, int(self._vram_crash_count or 0))

    def _has_scan_work(self) -> bool:
        if not self._session:
            return False
        return self._session.scan_count > 0 or bool(self.state.evidence_log)

    def _schedule_token_usage_snapshot_save(self) -> None:
        session = self._session
        if not session or not session.target:
            return

        current_time = time.time()
        if self._last_token_snapshot_time > 0:
            elapsed = current_time - self._last_token_snapshot_time
            if elapsed < 5.0:

                if (self._token_snapshot_task and
                        not self._token_snapshot_task.done()):
                    self._token_snapshot_resave_requested = True
                return

        self._last_token_snapshot_time = current_time

        if self._token_snapshot_task and not self._token_snapshot_task.done():
            self._token_snapshot_resave_requested = True
            return

        self._token_snapshot_resave_requested = False

        async def _save_worker(initial_session: SessionData) -> None:
            session_to_save: SessionData | None = initial_session
            try:
                while session_to_save and session_to_save.target:
                    try:

                        await asyncio.to_thread(save_session, session_to_save)
                    except Exception as exc:
                        logger.debug("Failed to persist token usage snapshot: %s", exc)
                    if not self._token_snapshot_resave_requested:
                        break
                    self._token_snapshot_resave_requested = False
                    session_to_save = self._session
            finally:
                self._token_snapshot_task = None

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            try:

                save_session(session)
            except Exception as exc:
                logger.debug("Failed to persist token usage snapshot: %s", exc)
            return

        self._token_snapshot_task = loop.create_task(_save_worker(session))

    def _record_token_usage(self, prompt_tokens: int, completion_tokens: int) -> None:
        prompt_tokens = max(0, int(prompt_tokens or 0))
        completion_tokens = max(0, int(completion_tokens or 0))
        total_tokens = prompt_tokens + completion_tokens
        if total_tokens <= 0:
            return

        usage = self.state.token_usage
        usage["used"] = total_tokens
        usage["last_prompt"] = prompt_tokens
        usage["last_completion"] = completion_tokens
        usage["cumulative"] = int(usage.get("cumulative", 0) or 0) + total_tokens
        usage["cumulative_prompt"] = int(
            usage.get("cumulative_prompt", 0) or 0
        ) + prompt_tokens
        usage["cumulative_completion"] = int(
            usage.get("cumulative_completion", 0) or 0
        ) + completion_tokens
        self._sync_token_usage_to_session()

        cumulative = usage.get("cumulative", 0)
        limit = usage.get("limit", 0)

        # Early warning: Save progress every 500 tokens (was 1000)
        if cumulative - self._last_saved_cumulative >= 500:
            self._last_saved_cumulative = cumulative
            self._schedule_token_usage_snapshot_save()

        # Log token budget status for long operations (every 10 iterations)
        if limit > 0 and self.state.iteration > 10 and self.state.iteration % 10 == 0:
            _budget_ratio = cumulative / limit
            if _budget_ratio >= 0.30:  # 30% threshold for logging
                logger.info(
                    "TOKEN BUDGET STATUS: cumulative=%d/%d (%.0f%%) — "
                    "prompt=%d, completion=%d, remaining_capacity=%.0f%%",
                    cumulative, limit, _budget_ratio * 100,
                    usage.get("cumulative_prompt", 0),
                    usage.get("cumulative_completion", 0),
                    (1 - _budget_ratio) * 100
                )

    def _recompute_used_tokens_from_conversation(self) -> int:
        text = "\n".join(
            str(msg.get("content", ""))
            for msg in self.state.conversation
            if isinstance(msg, dict)
        )
        used = max(0, int(_estimate_tokens(text)))
        self.state.token_usage["used"] = used
        return used
