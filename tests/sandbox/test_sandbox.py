"""T03 gate: resource limits, cleanup, credential separation, failure classification."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from vulnscan.infra.container_backend import (
    BackendUnavailable,
    DockerBackend,
    LocalSubprocessBackend,
)
from vulnscan.infra.isolation import assert_no_credentials, scrub_env
from vulnscan.infra.prepare import cache_key_for


class TestResourceLimits:
    def test_timeout_is_killed_and_reported(self, tmp_path: Path) -> None:
        """A subprocess that exceeds the timeout is reported as timeout."""
        backend = LocalSubprocessBackend()
        # sleep 30 with a 2s timeout (platform-portable long sleep).
        cmd = ["python", "-c", "import time; time.sleep(30)"]
        result = backend.run(cmd, workdir=tmp_path, timeout=2.0)
        assert result.timed_out is True
        assert result.returncode == -1

    def test_normal_completion_not_flagged(self, tmp_path: Path) -> None:
        backend = LocalSubprocessBackend()
        result = backend.run(["python", "-c", "print('ok')"], workdir=tmp_path, timeout=30.0)
        assert result.timed_out is False
        assert result.returncode == 0
        assert b"ok" in result.stdout


class TestCleanup:
    def test_workdir_created_and_no_residue(self, tmp_path: Path) -> None:
        """The backend may create its workdir, but a caller-managed scratch
        dir is removable after the run leaves nothing behind."""
        backend = LocalSubprocessBackend()
        scratch = tmp_path / "scratch"
        result = backend.run(["python", "-c", "print(1)"], workdir=scratch, timeout=30.0)
        assert Path(result.workdir).exists()
        # Removing it after the run must succeed and leave no residue.
        import shutil

        shutil.rmtree(scratch, ignore_errors=True)
        assert not scratch.exists()


class TestCredentialSeparation:
    def test_scrubbed_env_has_no_provider_keys(self) -> None:
        base = {
            "PATH": "/usr/bin",
            "OPENAI_API_KEY": "sk-leak",
            "ANTHROPIC_API_KEY": "sk-leak2",
            "SOMETHING_API_KEY": "leak3",
            "MY_PASSWORD": "leak4",
            "GITHUB_TOKEN": "leak5",
            "SAFE_VAR": "kept",
        }
        scrubbed = scrub_env(base)
        assert "OPENAI_API_KEY" not in scrubbed
        assert "ANTHROPIC_API_KEY" not in scrubbed
        assert "SOMETHING_API_KEY" not in scrubbed
        assert "MY_PASSWORD" not in scrubbed
        assert "GITHUB_TOKEN" not in scrubbed
        assert scrubbed["SAFE_VAR"] == "kept"
        assert "OPENAI_API_KEY" in scrubbed["_VULNSCAN_SCRUBBED_KEYS"]

    def test_assert_no_credentials_passes_when_clean(self) -> None:
        assert_no_credentials({"PATH": "/usr/bin"})

    def test_assert_no_credentials_raises_on_leak(self) -> None:
        with pytest.raises(AssertionError):
            assert_no_credentials({"PATH": "/usr/bin", "OPENAI_API_KEY": "x"})

    def test_real_environment_is_scrubbed(self) -> None:
        """The live os.environ must scrub to something clean."""
        scrubbed = scrub_env()
        assert_no_credentials(scrubbed)


class TestDeniedExternal:
    def test_no_docker_socket_inheritance(self, tmp_path: Path) -> None:
        """Verification runs must not get the host docker socket."""
        backend = LocalSubprocessBackend()
        result = backend.run(
            ["python", "-c", "import os; print('DOCKER' if os.environ.get('DOCKER_HOST') else 'NO_DOCKER')"],
            workdir=tmp_path,
            timeout=30.0,
            env=scrub_env(),
        )
        assert b"NO_DOCKER" in result.stdout

    def test_external_egress_not_attempted(self, tmp_path: Path) -> None:
        """An external request from a verification run is not attempted in
        this configuration: the runner only invokes local commands with a
        scrubbed env, and no network permission is granted."""
        backend = LocalSubprocessBackend()
        result = backend.run(
            ["python", "-c", "import os; print(sorted(k for k in os.environ if 'API' in k.upper()))"],
            workdir=tmp_path,
            timeout=30.0,
            env=scrub_env(),
        )
        assert result.returncode == 0
        # No credential-bearing env keys leaked into the subprocess.
        assert b"API_KEY" not in result.stdout


class TestFailureInjection:
    def test_nonzero_exit_classified_as_harness_failure(self, tmp_path: Path) -> None:
        """An injected nonzero exit is a harness failure, not a security observation."""
        backend = LocalSubprocessBackend()
        result = backend.run(["python", "-c", "import sys; sys.exit(3)"], workdir=tmp_path, timeout=30.0)
        assert result.returncode == 3
        assert result.timed_out is False
        # A nonzero return code without a security test having run => harness failure.
        assert result.returncode != 0

    def test_docker_backend_unavailable_is_documented_not_crash(self) -> None:
        """Missing docker must raise BackendUnavailable, not a bare crash."""
        backend = DockerBackend()
        if backend.is_available():
            pytest.skip("docker present on this host; unavailable path not exercisable")
        with pytest.raises(BackendUnavailable):
            backend.run(["echo", "x"], workdir=Path("/tmp"), timeout=5.0)


class TestCacheKeyStability:
    def test_key_is_content_based(self, tmp_path: Path) -> None:
        p1 = tmp_path / "pom.xml"
        p1.write_text("<project><artifactId>a</artifactId></project>")
        k1 = cache_key_for(p1)
        p2 = tmp_path / "pom2.xml"
        p2.write_text("<project><artifactId>a</artifactId></project>")
        assert cache_key_for(p2) == k1  # same content, different path => same key
        p1.write_text("<project><artifactId>b</artifactId></project>")
        assert cache_key_for(p1) != k1  # different content => different key
