import os
import shutil
import subprocess
from pathlib import Path

import pytest


BASH = shutil.which("bash")
WRAPPER = Path(__file__).resolve().parents[1] / "scripts/run_linux_release_build.sh"
pytestmark = pytest.mark.skipif(
    os.name != "posix" or BASH is None, reason="requires a POSIX shell"
)


@pytest.fixture
def docker_stub(tmp_path, monkeypatch):
    docker = tmp_path / "docker"
    docker.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")


@pytest.mark.parametrize(
    ("arguments", "architecture", "platform"),
    [
        ([], "x86_64", "amd64"),
        (["aarch64"], "aarch64", "arm64"),
        (["arm64"], "aarch64", "arm64"),
    ],
)
def test_release_wrapper_selects_image_and_platform(
    docker_stub, arguments, architecture, platform
):
    result = subprocess.run(
        [BASH, WRAPPER, *arguments], capture_output=True, text=True, check=True
    )

    docker_arguments = result.stdout.splitlines()
    assert docker_arguments[docker_arguments.index("--platform") + 1] == f"linux/{platform}"
    image, shell, script, target = docker_arguments[-4:]
    assert image.startswith(f"quay.io/pypa/manylinux2014_{architecture}@sha256:")
    digest = image.rsplit(":", 1)[1]
    assert len(digest) == 64
    int(digest, 16)
    assert (shell, script, target) == ("bash", "scripts/build_linux_release.sh", architecture)


def test_release_wrapper_rejects_unknown_architecture(docker_stub):
    result = subprocess.run(
        [BASH, WRAPPER, "armv7l"], capture_output=True, text=True, check=False
    )

    assert result.returncode != 0
    assert "Usage:" in result.stderr
    assert not result.stdout
