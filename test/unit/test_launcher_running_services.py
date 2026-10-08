"""Unit coverage for ``launcher.running_services``' checks that the process that serves a run is
the one it spawned: a stale process that already listens on a service's port stops the run
before any spawn (``wait_until_ready`` alone accepts any process that answers ``/health``), and a
spawned process that exits while it starts fails at once with its exit code.

No real subprocess and no network beyond the loopback. Untagged (unit lane); the module under test
is test infra (``test/system/launcher.py``), so the file sits at the ``test/unit/`` root, like
``test_launcher_event_path.py``."""

import socket
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from test.system.launcher import Service, require_port_free, running_services, wait_until_ready  # noqa: E402


@pytest.fixture
def held_port() -> Iterator[int]:
    """A port that a listening socket holds (a stale service)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        yield sock.getsockname()[1]


@pytest.fixture
def free_port() -> Iterator[int]:
    """A port that nothing listens on. It stays bound (no listen) for the test, so no other process
    can take it: a connect gets refused, the same as for a free port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        yield sock.getsockname()[1]


def test_a_held_port_stops_the_run_before_any_spawn(
    held_port: int, free_port: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    spawned: list[Service] = []
    monkeypatch.setattr("test.system.launcher.start_service", lambda service, *, src: spawned.append(service))
    services = [Service("free:app", port=free_port), Service("stale:app", port=held_port)]

    with pytest.raises(RuntimeError, match=f"127.0.0.1:{held_port} is already in use"):
        with running_services(services, src=Path(".")):
            pass

    assert spawned == []


def test_a_free_port_passes(free_port: int) -> None:
    require_port_free(Service("free:app", port=free_port))


def test_a_spawned_process_that_exits_fails_at_once_with_its_code(free_port: int) -> None:
    exited = SimpleNamespace(poll=lambda: 1)

    with pytest.raises(RuntimeError, match=r"exited \(code 1\) before it was ready"):
        wait_until_ready(f"http://127.0.0.1:{free_port}", timeout=30.0, proc=exited)
