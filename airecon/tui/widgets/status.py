"""Status bar widget: connection indicators, model info, tokens, skills, caido."""

from __future__ import annotations

from textual import events
from textual.message import Message
from textual.widgets import Label
from textual.containers import Horizontal
from textual.reactive import reactive


class StatusBar(Horizontal):
    """Bottom status bar showing services, tokens, skills, and caido status."""

    DEFAULT_CSS = """
    StatusBar {
        height: 1;
        background: $primary-darken-2;
        color: $text;
    }
    
    #status-skills {
        padding-left: 2;
        padding-right: 2;
    }
    
    #status-skills:hover {
        text-style: underline;
        background: $primary-darken-1;
        color: $text;
    }
    
    #status-caido-exec {
        padding-left: 2;
    }
    """

    class SkillsClicked(Message):
        """Emitted when the skills segment of the status bar is clicked."""
        pass

    ollama_status = reactive("offline")
    docker_status = reactive("offline")
    model_name = reactive("—")
    token_count = reactive(0)
    token_limit = reactive(65536)
    exec_used = reactive(0)
    subagents_spawned = reactive(0)
    skills_used: reactive[list[str]] = reactive(list)  # List of current skills
    caido_active = reactive(False)
    caido_findings = reactive(0)

    def compose(self):
        yield Label(id="status-metrics")
        yield Label(id="status-skills")
        yield Label(id="status-caido-exec")

    def on_mount(self) -> None:
        self._update_display()

    def on_click(self, event: events.Click) -> None:
        """Handle clicks on the status bar components."""
        # Find which widget was clicked
        widget, _ = self.screen.get_widget_at(*event.screen_offset)
        if widget and widget.id == "status-skills":
            self.post_message(self.SkillsClicked())

    def _update_display(self) -> None:
        try:
            # 1. Metrics part (Ollama, Docker, Model, Tokens)
            ollama_dot = "●" if self.ollama_status == "online" else "○"
            ollama_color = "#00d4aa" if self.ollama_status == "online" else "#ef4444"

            docker_dot = "●" if self.docker_status == "online" else "○"
            docker_color = "#00d4aa" if self.docker_status == "online" else "#ef4444"

            token_thousands = self.token_count / 1000.0
            if self.token_count < 20000:
                token_color = "#00d4aa"
            elif self.token_count < 50000:
                token_color = "#f59e0b"
            else:
                token_color = "#ef4444"

            metrics_text = (
                f" [{ollama_color}]{ollama_dot}[/] Ollama  "
                f"[{docker_color}]{docker_dot}[/] Docker  "
                f"│ [#8b949e]Model:[/] [#00d4aa]{self.model_name}[/]"
                f"  │ [#8b949e]Token:[/] [{token_color}]{token_thousands:.3f}k[/]"
            )
            self.query_one("#status-metrics", Label).update(metrics_text)

            # 2. Skills part
            skills_text = ""
            if self.skills_used:
                latest_skill = self.skills_used[-1]
                skills_text = f"│ [#8b949e]Skills:[/] [#818cf8]{latest_skill} <[/]"
            self.query_one("#status-skills", Label).update(skills_text)

            # 3. Caido / Exec / Shortcuts part
            caido_part = ""
            if self.caido_active:
                caido_part = f"│ [#ec4899]🔴 Caido[/] [#f87171]{self.caido_findings}[/] findings  "

            subagent_part = (
                f"  │ [#8b949e]Agents:[/] [#a78bfa]{self.subagents_spawned}[/]"
                if self.subagents_spawned > 0 else ""
            )

            caido_exec_text = (
                f"{caido_part}"
                f"│ [#8b949e]Exec:[/] [#f59e0b]{self.exec_used}[/]"
                f"{subagent_part}  "
                f"│ [#484f58]Ctrl+C quit · Ctrl+L clear[/]"
            )
            self.query_one("#status-caido-exec", Label).update(caido_exec_text)

        except Exception:
            pass

    def watch_ollama_status(self, _) -> None: self._update_display()
    def watch_docker_status(self, _) -> None: self._update_display()
    def watch_model_name(self, _) -> None: self._update_display()
    def watch_token_count(self, _) -> None: self._update_display()
    def watch_token_limit(self, _) -> None: self._update_display()
    def watch_exec_used(self, _) -> None: self._update_display()
    def watch_subagents_spawned(self, _) -> None: self._update_display()
    def watch_skills_used(self, _) -> None: self._update_display()
    def watch_caido_active(self, _) -> None: self._update_display()
    def watch_caido_findings(self, _) -> None: self._update_display()

    def set_status(
        self,
        ollama: str | None = None,
        docker: str | None = None,
        model: str | None = None,
        tokens: int | None = None,
        token_limit: int | None = None,
        tools: int | None = None,
        exec_used: int | None = None,
        subagents: int | None = None,
        skills: list[str] | None = None,
        caido_active: bool | None = None,
        caido_findings: int | None = None,
    ) -> None:
        if ollama is not None:
            self.ollama_status = ollama
        if docker is not None:
            self.docker_status = docker
        if model is not None:
            self.model_name = model
        if tokens is not None:
            self.token_count = tokens
        if token_limit is not None:
            self.token_limit = token_limit
        if exec_used is not None:
            self.exec_used = exec_used
        if subagents is not None:
            self.subagents_spawned = subagents
        if skills is not None:
            self.skills_used = skills
        if caido_active is not None:
            self.caido_active = caido_active
        if caido_findings is not None:
            self.caido_findings = caido_findings
