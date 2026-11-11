"""
scenes.py: the little fantasy animations shown while your code is being fixed.

One scene is picked at random each time:

  THE SHIELD    a sword flies at a shield and shatters against it
  THE FORTRESS  a dragon breathes fire at a castle wall, and the wall holds
  THE SPELL     a wizard casts a protection spell on a scroll (your code)

Each ends with a reassuring message, typed out letter by letter.

HOW A SCENE IS MADE
    A scene is a list of FRAMES, like the pages of a flip-book. Each frame
    is a few lines of text drawn on a "canvas" (a grid of letters). Showing
    the frames one after another, quickly, makes the picture move.

    This file only BUILDS the frames. ui.py draws them on screen. Keeping
    them apart means you can change a scene here without touching any
    drawing code, and the tests can check scenes without a screen.

TO ADD A SCENE
    Write a function that returns a Scene (copy one of the three below),
    then add it to the SCENES list at the bottom.
"""

from __future__ import annotations

import math  # sin() for the curved path of the sparkles
import random
from collections.abc import Callable
from dataclasses import dataclass, field

WIDTH = 60   # every scene is 60 letters wide...
HEIGHT = 7   # ...and 7 lines tall, plus one line underneath for the message


@dataclass
class Frame:
    """One picture in the flip-book."""

    lines: list[str]       # the picture, HEIGHT lines of text
    seconds: float         # how long to show it
    message: str = ""      # the line of text under the picture
    glowing: bool = False  # True = draw the hero (shield, wall, scroll) in bright green


@dataclass
class Scene:
    name: str
    frames: list[Frame]
    # Which colour each character is drawn in, e.g. {"~": "amber"}.
    # Characters not listed are drawn in the normal text colour.
    palette: dict[str, str] = field(default_factory=dict)
    # The characters that make up the hero, which turns green when it glows.
    hero: str = ""


class Canvas:
    """A blank grid of letters to draw on, WIDTH wide and HEIGHT tall.

    put() writes text at a position. Spaces in the text are see-through, so
    drawing a picture doesn't rub out what's behind it. Anything that falls
    off the edge is simply not drawn, so things can fly in from outside.
    """

    def __init__(self):
        # A list of rows, each a list of single letters. [" "] * WIDTH is a
        # list of WIDTH spaces (like Arrays.fill in Java).
        self.grid = [[" "] * WIDTH for _ in range(HEIGHT)]

    def put(self, x: int, y: int, text: str) -> None:
        for offset, letter in enumerate(text):
            column = x + offset
            if letter != " " and 0 <= column < WIDTH and 0 <= y < HEIGHT:
                self.grid[y][column] = letter

    def put_picture(self, x: int, y: int, picture: list[str]) -> None:
        """Draw a multi-line picture with its top-left corner at (x, y)."""
        for row, line in enumerate(picture):
            self.put(x, y + row, line)

    def frame(self, seconds: float, message: str = "", glowing: bool = False) -> Frame:
        return Frame(["".join(row) for row in self.grid], seconds, message, glowing)


def ending(draw: Callable[[], Canvas], message: str, frames: list[Frame]) -> None:
    """Add the last frames: the message types itself out, then stays a moment.

    `draw` is a function that draws the final picture. It's called once per
    frame, so the picture can be rebuilt each time.
    """
    for letters in range(0, len(message) + 1, 2):  # two letters per frame
        frames.append(draw().frame(0.025, message[:letters], glowing=True))
    frames.append(draw().frame(1.0, message, glowing=True))


# ===========================================================================
# THE SHIELD: a sword shatters against a shield
# ===========================================================================

SHIELD = [
    "╭─────╮",
    "│ ◆◆◆ │",
    "│  ◆  │",
    "╰╮   ╭╯",
    " ╰───╯",
]
SWORD = "o==[]:::::::::>"
SHIELD_MESSAGES = [
    "✦ Your code will be perfect ✦",
    "✦ No bug gets past this shield ✦",
    "✦ Every attack blocked. Your code is safe ✦",
]


def shield_scene(rng: random.Random) -> Scene:
    shield_x, shield_y = 44, 1
    sword_row = 3                                # the shield's middle line
    hit_x = shield_x - len(SWORD)                # where the sword stops: tip touching the shield
    frames: list[Frame] = []

    def with_shield() -> Canvas:
        canvas = Canvas()
        canvas.put_picture(shield_x, shield_y, SHIELD)
        return canvas

    # 1. The sword flies in from the left.
    for x in list(range(-len(SWORD), hit_x, 3)) + [hit_x]:
        canvas = with_shield()
        canvas.put(x, sword_row, SWORD)
        frames.append(canvas.frame(0.04))

    # 2. CLANG! Sparks fly off the shield.
    for sparks in (["✶", "*"], ["*", "✶"]):
        canvas = with_shield()
        canvas.put(hit_x, sword_row, SWORD)
        canvas.put(shield_x - 2, sword_row - 1, sparks[0])
        canvas.put(shield_x - 2, sword_row + 1, sparks[1])
        canvas.put(shield_x - 3, sword_row - 2, sparks[1])
        canvas.put(shield_x - 3, sword_row + 2, sparks[0])
        canvas.put(shield_x - 8, 0, "CLANG!")
        frames.append(canvas.frame(0.12))

    # 3. The sword breaks into pieces that bounce back and fall.
    #    Each piece: (text, starting x, speed sideways, speed up/down).
    pieces = [
        ("o==[]", hit_x, -1.5, 0.5),
        ("::::", hit_x + 5, -2.5, -0.6),
        (":::", hit_x + 9, -3.5, 0.7),
        (":>", hit_x + 13, -4.5, -0.9),
        ("·", hit_x + 14, -2.0, -1.3),
        ("·", hit_x + 14, -3.0, 1.2),
    ]
    for t in range(1, 8):  # t is time: each frame moves the pieces further
        canvas = with_shield()
        for text, x0, speed_x, speed_y in pieces:
            x = round(x0 + speed_x * t)
            y = round(sword_row + speed_y * t + 0.12 * t * t)  # + t*t: gravity pulls them down
            if t > 4:
                text = "." * min(len(text), 2)  # pieces crumble to dust
            canvas.put(x, y, text)
        frames.append(canvas.frame(0.07))

    # 4. The shield glows and the message appears.
    def glowing_shield() -> Canvas:
        canvas = with_shield()
        canvas.put(shield_x - 2, shield_y, "✦")
        canvas.put(shield_x + 8, shield_y + 4, "✦")
        return canvas

    ending(glowing_shield, rng.choice(SHIELD_MESSAGES), frames)
    palette = {letter: "cyan" for letter in "o=[]:>"}
    palette |= {letter: "amber" for letter in "╭─╮│╰╯◆✦"}  # |= adds the second dict into the first
    palette |= {letter: "coral" for letter in "✶*CLANG!·."}
    return Scene("The Shield", frames, palette, hero="╭─╮│╰╯◆✦")


# ===========================================================================
# THE FORTRESS: a dragon's fire can't break the castle wall
# ===========================================================================

DRAGON = [
    "    __/\\__",
    "   /  o   \\__",
    "  <   ____   =>",
    "   \\_/    \\_/",
]
WALL = ["▟▙▟▙"] + ["█▓▓█"] * (HEIGHT - 1)
FORTRESS_MESSAGES = [
    "✦ Nothing gets past these walls ✦",
    "✦ Your code is a fortress now ✦",
    "✦ Your code will be perfect ✦",
]


def fortress_scene(rng: random.Random) -> Scene:
    dragon_x, dragon_y = 1, 1
    mouth_row = dragon_y + 2
    fire_start = dragon_x + len(DRAGON[2]) + 1   # just past the dragon's mouth
    wall_x = 50
    fire_end = wall_x - 1                        # fire stops at the wall
    frames: list[Frame] = []

    def flames(length: int) -> str:
        return "".join(rng.choice("≈~≈") for _ in range(length))  # fresh flames each frame flicker

    def scene_with_fire(start: int, end: int, splash: bool = False) -> Canvas:
        canvas = Canvas()
        canvas.put_picture(dragon_x, dragon_y, DRAGON)
        canvas.put_picture(wall_x, 0, WALL)
        if end > start:
            canvas.put(start, mouth_row, flames(end - start))          # the main blast
            if end - start > 6:                                         # thinner flames above and below
                canvas.put(start + 3, mouth_row - 1, flames(end - start - 6).replace("≈", "~"))
                canvas.put(start + 3, mouth_row + 1, flames(end - start - 6).replace("≈", "~"))
        if splash:
            for row in (mouth_row - 2, mouth_row, mouth_row + 2):
                canvas.put(fire_end, row, rng.choice("✶*"))
        return canvas

    # 1. The fire grows from the dragon's mouth to the wall.
    for end in list(range(fire_start, fire_end, 3)) + [fire_end]:
        frames.append(scene_with_fire(fire_start, end).frame(0.05))

    # 2. The fire hits the wall and splashes, but the wall doesn't break.
    for _ in range(5):
        frames.append(scene_with_fire(fire_start, fire_end, splash=True).frame(0.08))

    # 3. The dragon runs out of breath: the fire shrinks away.
    for start in range(fire_start, fire_end + 1, 6):
        frames.append(scene_with_fire(start, fire_end).frame(0.06))

    # 4. The wall glows and the message appears.
    ending(lambda: scene_with_fire(0, 0), rng.choice(FORTRESS_MESSAGES), frames)
    palette = {letter: "coral" for letter in "_/\\<>=o"}
    palette |= {letter: "amber" for letter in "≈~✶*"}
    palette |= {letter: "cyan" for letter in "▟▙█▓"}
    return Scene("The Fortress", frames, palette, hero="▟▙█▓")


# ===========================================================================
# THE SPELL: a wizard protects the scroll
# ===========================================================================

WIZARD = [
    "    ▲      ✦",
    "   /*\\     |",
    "  (o.o)    |",
    "  /|=|\\___/|",
    "   / \\     |",
]
SCROLL = [
    "┌───────┐",
    "│ ≡≡≡≡≡ │",
    "│ ≡≡≡≡≡ │",
    "│ ≡≡≡≡≡ │",
    "└───────┘",
]
SPELL_MESSAGES = [
    "✦ Your code is under a protection spell ✦",
    "✦ Your code will be perfect ✦",
    "✦ A spell of safety is cast on your code ✦",
]


def spell_scene(rng: random.Random) -> Scene:
    wizard_x, wizard_y = 1, 1
    staff_tip = (wizard_x + 11, wizard_y)              # the ✦ at the top of the staff
    scroll_x, scroll_y = 42, 1
    target = (scroll_x - 1, scroll_y + 2)              # just left of the scroll's middle
    frames: list[Frame] = []

    def base() -> Canvas:
        canvas = Canvas()
        canvas.put_picture(wizard_x, wizard_y, WIZARD)
        canvas.put_picture(scroll_x, scroll_y, SCROLL)
        return canvas

    # 1. Sparkles fly from the staff to the scroll along a curved path.
    #    Each sparkle starts 2 frames after the one before it.
    sparkles = 5
    travel_frames = 10
    for frame_number in range(sparkles * 2 + travel_frames):
        canvas = base()
        for sparkle in range(sparkles):
            progress = (frame_number - sparkle * 2) / travel_frames  # 0.0 = at the staff, 1.0 = arrived
            if not 0 <= progress <= 1:
                continue  # not launched yet, or already arrived
            x = staff_tip[0] + (target[0] - staff_tip[0]) * progress
            # sin() makes an arch: 0 at both ends, highest in the middle.
            y = staff_tip[1] + (target[1] - staff_tip[1]) * progress - 2 * math.sin(math.pi * progress)
            canvas.put(round(x), round(y), "✦✧·"[(frame_number + sparkle) % 3])
        frames.append(canvas.frame(0.05))

    # 2. A magic ring forms around the scroll, with a bright light running round it.
    ring = ring_around(scroll_x - 2, 0, scroll_x + len(SCROLL[0]) + 1, HEIGHT - 1)

    def with_ring(bright: int | None = None) -> Canvas:
        canvas = base()
        for number, (x, y) in enumerate(ring):
            if number % 2 == 0:            # every other point, so the ring looks dotted
                canvas.put(x, y, "·")
        if bright is not None:
            x, y = ring[bright % len(ring)]
            canvas.put(x, y, "✦")
        return canvas

    for step in range(0, len(ring), 2):
        frames.append(with_ring(bright=step).frame(0.035))

    # 3. The scroll glows and the message appears.
    ending(with_ring, rng.choice(SPELL_MESSAGES), frames)
    palette = {letter: "cyan" for letter in "▲/*\\(o.)|=_"}
    palette |= {letter: "amber" for letter in "✦✧·"}
    return Scene("The Spell", frames, palette, hero="┌─┐│└┘≡·✦")


def ring_around(left: int, top: int, right: int, bottom: int) -> list[tuple[int, int]]:
    """The points of a rectangle's outline, going clockwise from the top-left."""
    points = [(x, top) for x in range(left, right + 1)]                # top edge, left to right
    points += [(right, y) for y in range(top + 1, bottom)]             # right edge, downwards
    points += [(x, bottom) for x in range(right, left - 1, -1)]        # bottom edge, right to left
    points += [(left, y) for y in range(bottom - 1, top, -1)]          # left edge, upwards
    return points


# ===========================================================================
# PICKING A SCENE
# ===========================================================================

SCENES = [shield_scene, fortress_scene, spell_scene]


def random_scene(seed: int | None = None) -> Scene:
    """Pick one of the scenes at random.

    A "seed" makes the randomness repeatable: the same seed always gives
    the same scene and flames. The tests use that; normal runs don't.
    """
    rng = random.Random(seed)
    return rng.choice(SCENES)(rng)
