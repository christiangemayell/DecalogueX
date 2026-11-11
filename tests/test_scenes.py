"""
Tests for the fantasy scenes (scenes.py).

These check the flip-book frames themselves, without drawing anything:
every frame must be the right size, or the animation would leave
leftover bits on the screen.
"""

import random

import pytest

from decaloguex import scenes


# @pytest.mark.parametrize runs the test once per scene, like JUnit's
# @ParameterizedTest. Each run shows up as its own test.
@pytest.mark.parametrize("make_scene", scenes.SCENES)
def test_every_frame_fits(make_scene):
    scene = make_scene(random.Random(0))
    for frame in scene.frames:
        assert len(frame.lines) == scenes.HEIGHT
        assert all(len(line) <= scenes.WIDTH for line in frame.lines)
        assert len(frame.message) <= scenes.WIDTH


@pytest.mark.parametrize("make_scene", scenes.SCENES)
def test_scene_ends_with_a_reassuring_message(make_scene):
    scene = make_scene(random.Random(0))
    last = scene.frames[-1]
    assert last.message.startswith("✦") and last.message.endswith("✦")  # a full message, typed out
    assert last.glowing


@pytest.mark.parametrize("make_scene", scenes.SCENES)
def test_scene_length_is_a_few_seconds(make_scene):
    seconds = sum(frame.seconds for frame in make_scene(random.Random(0)).frames)
    assert 1.5 <= seconds <= 4.0


def test_same_seed_gives_the_same_scene():
    first = scenes.random_scene(seed=42)
    second = scenes.random_scene(seed=42)
    assert first.name == second.name
    assert [f.lines for f in first.frames] == [f.lines for f in second.frames]


def test_all_three_scenes_can_be_picked():
    names = {scenes.random_scene(seed=n).name for n in range(50)}
    assert names == {"The Shield", "The Fortress", "The Spell"}
