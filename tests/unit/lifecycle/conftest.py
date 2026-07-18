from collections.abc import Iterator

import pykka
import pytest


@pytest.fixture(autouse=True)
def stop_actors() -> Iterator[None]:
    yield
    pykka.ActorRegistry.stop_all(block=True, timeout=2)
    assert not pykka.ActorRegistry.get_all()
