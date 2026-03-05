"""Modal screen to display the list of currently loaded skills."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical, Container
from textual.screen import ModalScreen
from textual.widgets import Label, Button, Markdown


class SkillsModal(ModalScreen):
    """A modal popup showing all skills currently loaded into the agent's context."""

    DEFAULT_CSS = """
    SkillsModal {
        align: center middle;
    }
    
    #skills-dialog {
        width: 60;
        height: auto;
        max-height: 80%;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
        border-title-color: $accent;
    }
    
    #skills-title {
        text-align: center;
        width: 100%;
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    
    #skills-content {
        height: auto;
        max-height: 60%;
        overflow-y: auto;
        margin-bottom: 1;
        padding: 1;
        background: $background;
        border: solid $surface-light;
    }
    
    #skills-close-container {
        align: center bottom;
        width: 100%;
    }
    """

    def __init__(self, skills: list[str], *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.skills = skills

    def compose(self) -> ComposeResult:
        with Container(id="skills-dialog"):
            yield Label(f"Loaded Skills ({len(self.skills)})", id="skills-title")
            
            # Format skills as a markdown list for better readability
            skills_md = "\n".join(f"- `{skill}`" for skill in self.skills) if self.skills else "*No skills loaded yet*"
            
            with Vertical(id="skills-content"):
                yield Markdown(skills_md)
                
            with Container(id="skills-close-container"):
                yield Button("Close", variant="primary", id="skills-close-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "skills-close-btn":
            self.app.pop_screen()
