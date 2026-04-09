from __future__ import annotations

from typing import Literal

Species = Literal[
    "duck",
    "goose",
    "blob",
    "cat",
    "dragon",
    "octopus",
    "owl",
    "penguin",
    "turtle",
    "snail",
    "ghost",
    "axolotl",
    "capybara",
    "cactus",
    "robot",
    "rabbit",
    "mushroom",
    "chonk"
]

BODIES: dict[Species, list[list[str]]] = {
    "duck": [
        [
            "            ",
            "    __      ",
            "  <(o )___  ",
            "   (  ._>   ",
            "    `--´    ",
        ],
        [
            "            ",
            "    __      ",
            "  <(o )___  ",
            "   (  ._>   ",
            "    `--´~   ",
        ],
        [
            "            ",
            "    __      ",
            "  <(o )___  ",
            "   (  .__>  ",
            "    `--´    ",
        ],
    ],
    "goose": [
        [
            "            ",
            "     (o>    ",
            "     ||     ",
            "   _(__)_   ",
            "    ^^^^    ",
        ],
        [
            "            ",
            "    (o>     ",
            "     ||     ",
            "   _(__)_   ",
            "    ^^^^    ",
        ],
        [
            "            ",
            "     (o>>   ",
            "     ||     ",
            "   _(__)_   ",
            "    ^^^^    ",
        ],
    ],
    "blob": [
        [
            "            ",
            "   .----.   ",
            "  ( o  o )  ",
            "  (      )  ",
            "   `----´   ",
        ],
        [
            "            ",
            "  .------.  ",
            " (  o  o  ) ",
            " (        ) ",
            "  `------´  ",
        ],
        [
            "            ",
            "    .--.    ",
            "   (o  o)   ",
            "   (    )   ",
            "    `--´    ",
        ],
    ],
    "cat": [
        [
            "            ",
            "   /\\_/\\    ",
            "  ( o   o)  ",
            "  (  ω  )   ",
            "  (\")_(\")   ",
        ],
        [
            "            ",
            "   /\\_/\\    ",
            "  ( o   o)  ",
            "  (  ω  )   ",
            "  (\")_(\")~  ",
        ],
        [
            "            ",
            "   /\\-/\\    ",
            "  ( o   o)  ",
            "  (  ω  )   ",
            "  (\")_(\")   ",
        ],
    ],
    "dragon": [
        [
            "            ",
            "  /^\\  /^\\  ",
            " <  o  o  > ",
            " (   ~~   ) ",
            "  `-vvvv-´  ",
        ],
        [
            "            ",
            "  /^\\  /^\\  ",
            " <  o  o  > ",
            " (        ) ",
            "  `-vvvv-´  ",
        ],
        [
            "   ~    ~   ",
            "  /^\\  /^\\  ",
            " <  o  o  > ",
            " (   ~~   ) ",
            "  `-vvvv-´  ",
        ],
    ],
    "octopus": [
        [
            "            ",
            "   .----.   ",
            "  ( o  o )  ",
            "  (______)  ",
            "  /\\/\\/\\/\\  ",
        ],
        [
            "            ",
            "   .----.   ",
            "  ( o  o )  ",
            "  (______)  ",
            "  \\/\\/\\/\\/  ",
        ],
        [
            "     o      ",
            "   .----.   ",
            "  ( o  o )  ",
            "  (______)  ",
            "  /\\/\\/\\/\\  ",
        ],
    ],
    "owl": [
        [
            "            ",
            "   /\\  /\\   ",
            "  ((o)(o))  ",
            "  (  ><  )  ",
            "   `----´   ",
        ],
        [
            "            ",
            "   /\\  /\\   ",
            "  ((o)(o))  ",
            "  (  ><  )  ",
            "   .----.   ",
        ],
        [
            "            ",
            "   /\\  /\\   ",
            "  ((o)(-))  ",
            "  (  ><  )  ",
            "   `----´   ",
        ],
    ],
    "penguin": [
        [
            "            ",
            "  .---.     ",
            "  (o>o)     ",
            " /(   )\\    ",
            "  `---´     ",
        ],
        [
            "            ",
            "  .---.     ",
            "  (o>o)     ",
            " |(   )|    ",
            "  `---´     ",
        ],
        [
            "  .---.     ",
            "  (o>o)     ",
            " /(   )\\    ",
            "  `---´     ",
            "   ~ ~      ",
        ],
    ],
    "turtle": [
        [
            "            ",
            "   _,--._   ",
            "  ( o  o )  ",
            " /[______]\\ ",
            "  ``    ``  ",
        ],
        [
            "            ",
            "   _,--._   ",
            "  ( o  o )  ",
            " /[______]\\ ",
            "   ``  ``   ",
        ],
        [
            "            ",
            "   _,--._   ",
            "  ( o  o )  ",
            " /[======]\\ ",
            "  ``    ``  ",
        ],
    ],
    "snail": [
        [
            "    what    ",
            "            ",
            "            ",
            " o    .--.  ",
            "  \\  ( @ )  ",
            "   \\_`--´   ",
            "  ~~~~~~~   ",
        ],
        [
            "     The    ",
            "            ",
            "            ",
            "  o   .--.  ",
            "  |  ( @ )  ",
            "   \\_`--´   ",
            "  ~~~~~~~   ",
        ],
        [
            "     Fuck.. ",
            "            ",
            " o    .--.  ",
            "  \\  ( @  ) ",
            "   \\_`--´   ",
            "   ~~~~~~   ",
        ],
    ],
    "ghost": [
        [
            "            ",
            "   .----.   ",
            "  / o  o \\  ",
            "  |      |  ",
            "  ~`~``~`~  ",
        ],
        [
            "            ",
            "   .----.   ",
            "  / o  o \\  ",
            "  |      |  ",
            "  `~`~~`~`  ",
        ],
        [
            "    ~  ~    ",
            "   .----.   ",
            "  / o  o \\  ",
            "  |      |  ",
            "  ~~`~~`~~  ",
        ],
    ],
    "axolotl": [
        [
            "            ",
            "}~(______)~{",
            "}~(o .. o)~{",
            "  ( .--. )  ",
            "  (_/  \\_)  ",
        ],
        [
            "            ",
            "~}(______){~",
            "~}(o .. o){~",
            "  ( .--. )  ",
            "  (_/  \\_)  ",
        ],
        [
            "            ",
            "}~(______)~{",
            "}~(o .. o)~{",
            "  (  --  )  ",
            "  ~_/  \\_~  ",
        ],
    ],
    "capybara": [
        [
            "            ",
            "  n______n  ",
            " ( o    o ) ",
            " (   oo   ) ",
            "  `------´  ",
        ],
        [
            "            ",
            "  n______n  ",
            " ( o    o ) ",
            " (   Oo   ) ",
            "  `------´  ",
        ],
        [
            "    ~  ~    ",
            "  u______n  ",
            " ( o    o ) ",
            " (   oo   ) ",
            "  `------´  ",
        ],
    ],
    "cactus": [
        [
            "            ",
            " n  ____  n ",
            " | |o  o| | ",
            " |_|    |_| ",
            "   |    |   ",
        ],
        [
            "            ",
            "    ____    ",
            " n |o  o| n ",
            " |_|    |_| ",
            "   |    |   ",
        ],
        [
            " n        n ",
            " |  ____  | ",
            " | |o  o| | ",
            " |_|    |_| ",
            "   |    |   ",
        ],
    ],
    "robot": [
        [
            "            ",
            "   .[||].   ",
            "  [ o  o ]  ",
            "  [ ==== ]  ",
            "  `------´  ",
        ],
        [
            "            ",
            "   .[||].   ",
            "  [ o  o ]  ",
            "  [ -==- ]  ",
            "  `------´  ",
        ],
        [
            "     *      ",
            "   .[||].   ",
            "  [ o  o ]  ",
            "  [ ==== ]  ",
            "  `------´  ",
        ],
    ],
    "rabbit": [
        [
            "            ",
            "   (\\__/)   ",
            "  ( o  o )  ",
            " =(  ..  )= ",
            "  (\")__(\")  ",
        ],
        [
            "            ",
            "   (|__/)   ",
            "  ( o  o )  ",
            " =(  ..  )= ",
            "  (\")__(\")  ",
        ],
        [
            "            ",
            "   (\\__/)   ",
            "  ( o  o )  ",
            " =( .  . )= ",
            "  (\")__(\")  ",
        ],
    ],
    "mushroom": [
        [
            "            ",
            " .-o-OO-o-. ",
            "(__________)",
            "   |o  o|   ",
            "   |____|   ",
        ],
        [
            "            ",
            " .-O-oo-O-. ",
            "(__________)",
            "   |o  o|   ",
            "   |____|   ",
        ],
        [
            "   . o  .   ",
            " .-o-OO-o-. ",
            "(__________)",
            "   |o  o|   ",
            "   |____|   ",
        ],
    ],
    "chonk": [
        [
            "            ",
            "  /\\    /\\  ",
            " ( o    o ) ",
            " (   ..   ) ",
            "  `------´  ",
        ],
        [
            "            ",
            "  /\\    /|  ",
            " ( o    o ) ",
            " (   ..   ) ",
            "  `------´  ",
        ],
        [
            "            ",
            "  /\\    /\\  ",
            " ( o    o ) ",
            " (   ..   ) ",
            "  `------´~ ",
        ],
    ],
}

AVAILABLE_SPECIES: list[Species] = list(BODIES.keys())

PALETTES: list[list[str]] = [
    ["#94a3b8", "#60a5fa", "#34d399", "#60a5fa", "#94a3b8"],
    ["#f59e0b", "#f97316", "#fb7185", "#f97316", "#f59e0b"],
    ["#22d3ee", "#38bdf8", "#60a5fa", "#38bdf8", "#22d3ee"],
    ["#a78bfa", "#c084fc", "#f472b6", "#c084fc", "#a78bfa"],
    ["#86efac", "#34d399", "#10b981", "#34d399", "#86efac"],
]

PHASE_PALETTES: dict[str, list[str]] = {
    "RECON": ["#38bdf8", "#22d3ee", "#10b981", "#22d3ee", "#38bdf8"],
    "ANALYSIS": ["#a78bfa", "#c084fc", "#f472b6", "#c084fc", "#a78bfa"],
    "EXPLOIT": ["#f97316", "#f59e0b", "#ef4444", "#f59e0b", "#f97316"],
    "REPORT": ["#34d399", "#86efac", "#22c55e", "#86efac", "#34d399"],
}

PHASE_SPECIES_POOL: dict[str, list[Species]] = {
    "RECON": ["owl", "duck", "goose", "penguin", "snail"],
    "ANALYSIS": ["octopus", "cat", "blob", "axolotl"],
    "EXPLOIT": ["dragon", "robot", "ghost", "chonk"],
    "REPORT": ["turtle", "capybara", "cactus", "rabbit", "mushroom"],
}

STATE_PALETTES: dict[str, list[str]] = {
    "thinking": ["#94a3b8", "#8b949e", "#cbd5f5", "#8b949e", "#94a3b8"],
    "tool": ["#60a5fa", "#38bdf8", "#22d3ee", "#38bdf8", "#60a5fa"],
    "wait": ["#facc15", "#f59e0b", "#fbbf24", "#f59e0b", "#facc15"],
    "error": ["#ef4444", "#f97316", "#b91c1c", "#f97316", "#ef4444"],
    "idle": ["#6b7280", "#94a3b8", "#cbd5f5", "#94a3b8", "#6b7280"],
}

TOOL_PALETTES: dict[str, list[str]] = {
    "browser": ["#22d3ee", "#38bdf8", "#60a5fa", "#38bdf8", "#22d3ee"],
    "fuzz": ["#f472b6", "#c084fc", "#a78bfa", "#c084fc", "#f472b6"],
}

PRESSURE_PALETTES: dict[str, list[str]] = {
    "warning": ["#f59e0b", "#fbbf24", "#f59e0b", "#fbbf24", "#f59e0b"],
    "critical": ["#ef4444", "#f97316", "#b91c1c", "#f97316", "#ef4444"],
}

SPECIES_PALETTES: dict[Species, list[str]] = {
    "duck": ["#7dd3fc", "#38bdf8", "#0ea5e9", "#38bdf8", "#7dd3fc"],
    "goose": ["#e2e8f0", "#cbd5f5", "#94a3b8", "#cbd5f5", "#e2e8f0"],
    "blob": ["#a7f3d0", "#6ee7b7", "#34d399", "#6ee7b7", "#a7f3d0"],
    "cat": ["#fbcfe8", "#f9a8d4", "#f472b6", "#f9a8d4", "#fbcfe8"],
    "dragon": ["#fb7185", "#f43f5e", "#ef4444", "#f43f5e", "#fb7185"],
    "octopus": ["#c4b5fd", "#a78bfa", "#8b5cf6", "#a78bfa", "#c4b5fd"],
    "owl": ["#fde68a", "#facc15", "#f59e0b", "#facc15", "#fde68a"],
    "penguin": ["#bae6fd", "#7dd3fc", "#38bdf8", "#7dd3fc", "#bae6fd"],
    "turtle": ["#bbf7d0", "#86efac", "#22c55e", "#86efac", "#bbf7d0"],
    "snail": ["#fecaca", "#fda4af", "#fb7185", "#fda4af", "#fecaca"],
    "ghost": ["#f1f5f9", "#e2e8f0", "#cbd5f5", "#e2e8f0", "#f1f5f9"],
    "axolotl": ["#fce7f3", "#f9a8d4", "#f472b6", "#f9a8d4", "#fce7f3"],
    "capybara": ["#fde68a", "#fbbf24", "#f59e0b", "#fbbf24", "#fde68a"],
    "cactus": ["#86efac", "#4ade80", "#22c55e", "#4ade80", "#86efac"],
    "robot": ["#cbd5f5", "#94a3b8", "#64748b", "#94a3b8", "#cbd5f5"],
    "rabbit": ["#e9d5ff", "#c4b5fd", "#a78bfa", "#c4b5fd", "#e9d5ff"],
    "mushroom": ["#fecdd3", "#fda4af", "#fb7185", "#fda4af", "#fecdd3"],
    "chonk": ["#fdba74", "#fb923c", "#f97316", "#fb923c", "#fdba74"],
}

def get_frames(species: Species) -> list[list[str]]:
    return BODIES.get(species, BODIES["duck"])

def get_frame(species: Species, frame_index: int) -> list[str]:
    frames = get_frames(species)
    return frames[frame_index % len(frames)]

def _expand_palette(palette: list[str], rows: int) -> list[str]:
    if rows <= len(palette):
        return palette[:rows]
    return [palette[i % len(palette)] for i in range(rows)]

def get_palette(index: int, rows: int = 5) -> list[str]:
    if not PALETTES:
        return ["#8b949e"] * rows
    palette = PALETTES[index % len(PALETTES)]
    return _expand_palette(palette, rows)

def get_buddy_palette(
    *,
    species: str | None,
    state: str | None,
    phase: str | None,
    pressure: float | None,
    tool_kind: str | None,
    index: int,
    rows: int = 5,
) -> list[str]:
    if pressure is not None:
        if pressure >= 0.85:
            return _expand_palette(PRESSURE_PALETTES["critical"], rows)
        if pressure >= 0.65:
            return _expand_palette(PRESSURE_PALETTES["warning"], rows)

    if species:
        palette = SPECIES_PALETTES.get(species)
        if palette:
            return _expand_palette(palette, rows)

    if tool_kind:
        tool_key = tool_kind.lower()
        if tool_key in TOOL_PALETTES:
            return _expand_palette(TOOL_PALETTES[tool_key], rows)

    if state:
        state_key = state.lower()
        if state_key in STATE_PALETTES:
            return _expand_palette(STATE_PALETTES[state_key], rows)

    if phase:
        phase_key = phase.upper()
        if phase_key in PHASE_PALETTES:
            return _expand_palette(PHASE_PALETTES[phase_key], rows)

    return get_palette(index, rows)

def get_species_pool_for_phase(phase: str | None) -> list[Species] | None:
    if not phase:
        return None
    return PHASE_SPECIES_POOL.get(str(phase).upper())
