"""Unit coverage for ``launcher.running_services``' port check: a stale process that already
listens on a service's port must stop the run before any spawn, not serve it in place of the new
service (``wait_until_ready`` accepts any process that answers ``/health``).

No subprocess and no network beyond the loopback: the test holds a listening socket on a free
port and checks that ``running_services`` refuses it. Untagged (unit lane); the module under test is
test infra (``test/system/launcher.py``), so the file sits at the ``test/unit/`` root, like
``test_launcher_event_path.py``."""

import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from test.system.launcher import Service, require_port_free, running_services  # noqa: E402


@pytest.fixture
def held_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        yield sock.getsockname()[1]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_a_held_port_stops_the_run_before_any_spawn(held_port: int, monkeypatch: pytest.MonkeyPatch) -> None:
    spawned: list[Service] = []
    monkeypatch.setattr("test.system.launcher.start_service", lambda service, *, src: spawned.append(service))
    services = [Service("free:app", port=_free_port()), Service("stale:app", port=held_port)]

    with pytest.raises(RuntimeError, match=f"127.0.0.1:{held_port} is already in use"):
        with running_services(services, src=Path(".")):
            pass

    assert spawned == []


def test_a_free_port_passes() -> None:
    require_port_free(Service("free:app", port=_free_port()))
