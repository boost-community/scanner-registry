"""Fail when the pinned trivy's log stops matching what the converters parse.

The trivy converters read trivy's log, not only its report: a `Failed to fetch`
DEBUG record is their only sign of a throttled Maven Central (trivy < 0.71), and a
`Number of language-specific files` record of a repository with no lockfile.
Both are undocumented trivy wording: reworded, the converters' fetch counts
silently read 0 and the no-lockfile error silently disappears.

From trivy 0.71 (aquasecurity/trivy#10693) a throttled Maven fetch is no longer
logged and skipped: trivy fails the scan with a FATAL record and exits non-zero,
so the module fails the scan and the converters never run. That fail-fast
outcome is accepted; for those pins the canary checks it instead of the DEBUG
record, so that a return to the old behaviour (or a reworded error) is noticed.

Runs in a container whose repo.maven.apache.org resolves to this process.
"""

import gzip
import hashlib
import http.server
import json
import os
import platform
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path
from typing import NamedTuple

# The regexes of boostsec-scanner-trivy and boostsec-scanner-trivy-sbom's
# process.py (trivy's NUM_LANG_FILES_RE matches the same record): change together.
LOG_LINE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\S+\s+(\w+)\s+(.*)")
FETCH_FAILURE_RE = re.compile(r"^\[([^\]]+)\] Failed to fetch\s")
THROTTLED_RE = re.compile(r"\sstatusCode=429\b")
NO_LANG_FILES_RE = re.compile(r"Number of language-specific files.*num=0$")
MAVEN_PARSER = "pom"
# trivy >= 0.71 fails the scan on a throttled Maven fetch (aquasecurity/trivy#10693).
THROTTLED_FAILS_SCAN_SINCE = (0, 71, 0)
THROTTLED_FATAL_RE = re.compile(r"remote Maven repository returned 429 Too Many Requests")

TRIVY_URL = "https://assets.build.boostsecurity.io/scanners/trivy/trivy-{version}/linux/{arch}/trivy.gz"
ARCHES = {
    "x86_64": ("amd64", "LINUX_X86_64_SHA"),
    "aarch64": ("arm64", "LINUX_ARM64_SHA"),
}
FIXTURE = Path(__file__).parent / "fixture"


class Scan(NamedTuple):
    """How a trivy scan ended, and its log."""

    exit_code: int
    log: str


class Record(NamedTuple):
    """A trivy log record."""

    level: str
    message: str


def main() -> None:
    """Scan a pom.xml with Central unreachable, then throttling, then an empty dir."""
    pin = json.loads(os.environ["TRIVY_PIN"])
    workdir = Path(tempfile.mkdtemp())
    trivy = download_trivy(pin, workdir)
    key, cert = create_certificate(workdir)

    unreachable = scan(trivy, cert, FIXTURE)
    serve_throttled(key, cert)
    throttled = scan(trivy, cert, FIXTURE)
    no_language_files = scan(trivy, cert, Path(tempfile.mkdtemp()))

    if version(pin["VERSION"]) >= THROTTLED_FAILS_SCAN_SINCE:
        throttled_check = (
            "a throttled Maven fetch failing the scan (THROTTLED_FATAL_RE, exit != 0)",
            throttled,
            fails_on_throttled_maven_fetch,
        )
    else:
        throttled_check = (
            "a throttled Maven fetch (FETCH_FAILURE_RE, THROTTLED_RE)",
            throttled,
            logs_a_throttled_maven_fetch,
        )

    checks = (
        ("a failed Maven fetch (FETCH_FAILURE_RE)", unreachable, logs_a_maven_fetch),
        throttled_check,
        (
            "no language files (NO_LANG_FILES_RE)",
            no_language_files,
            logs_no_language_files,
        ),
    )
    broken = [
        f"{contract} (exit {result.exit_code}):\n{result.log}"
        for contract, result, holds in checks
        if not holds(result)
    ]

    if broken:
        sys.exit(
            f"trivy {pin['VERSION']} no longer logs these as the converters in"
            " boostsec-scanner-trivy and boostsec-scanner-trivy-sbom parse them;"
            " update both before bumping trivy.\n\n" + "\n\n".join(broken)
        )

    print(f"trivy {pin['VERSION']}: log matches what the converters parse")


def version(text: str) -> tuple[int, ...]:
    """Parse a trivy version such as 0.76.2."""
    return tuple(int(part) for part in text.split("."))


def download_trivy(pin: dict[str, str], workdir: Path) -> Path:
    """Download the module-pinned trivy, verified against the module's checksum."""
    arch, sha_key = ARCHES[platform.machine()]
    url = TRIVY_URL.format(version=pin["VERSION"], arch=arch)
    with urllib.request.urlopen(url) as response:
        data = response.read()

    if hashlib.sha256(data).hexdigest() != pin[sha_key]:
        sys.exit(f"{url}: checksum does not match the module's {sha_key}")

    trivy = workdir / "trivy"
    trivy.write_bytes(gzip.decompress(data))
    trivy.chmod(0o755)
    return trivy


def create_certificate(workdir: Path) -> tuple[Path, Path]:
    """Create a self-signed certificate for repo.maven.apache.org."""
    key, cert = workdir / "key.pem", workdir / "cert.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=repo.maven.apache.org",
            "-addext",
            "subjectAltName=DNS:repo.maven.apache.org",
            "-keyout",
            key,
            "-out",
            cert,
        ],
        check=True,
        capture_output=True,
    )
    return key, cert


def serve_throttled(key: Path, cert: Path) -> None:
    """Answer every HTTPS request on port 443 with a 429."""

    class Throttled(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(429)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = http.server.HTTPServer(("127.0.0.1", 443), Throttled)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def scan(trivy: Path, cert: Path, target: Path) -> Scan:
    """Scan a directory and return its exit code and trivy's log.

    The CycloneDX format needs no vulnerability DB, which keeps the scan offline
    but for its Maven fetches.
    """
    result = subprocess.run(
        [
            trivy,
            "fs",
            "--debug",
            "--format",
            "cyclonedx",
            "--no-progress",
            "--skip-version-check",
            "--cache-dir",
            tempfile.mkdtemp(),
            target,
        ],
        check=False,
        env={**os.environ, "SSL_CERT_FILE": str(cert)},
        capture_output=True,
        text=True,
    )
    return Scan(exit_code=result.returncode, log=result.stderr)


def records(log: str) -> list[Record]:
    """Split a log into its records, folding indented lines into the one above.

    The converters do the same: a FATAL record spans several lines.
    """
    found: list[Record] = []
    for line in log.splitlines():
        if match := LOG_LINE_RE.match(line):
            found.append(Record(level=match.group(1), message=match.group(2)))
        elif found and line[:1].isspace():
            found[-1] = found[-1]._replace(message=f"{found[-1].message}\n{line}")
    return found


def logs_a_maven_fetch(result: Scan) -> bool:
    """Whether the scan logged a failed Maven fetch."""
    return any(is_maven_fetch(record) for record in records(result.log))


def logs_a_throttled_maven_fetch(result: Scan) -> bool:
    """Whether the scan logged a throttled Maven fetch (trivy < 0.71)."""
    return any(is_throttled_maven_fetch(record) for record in records(result.log))


def fails_on_throttled_maven_fetch(result: Scan) -> bool:
    """Whether a throttled Maven fetch failed the scan (trivy >= 0.71).

    The module then fails the scan with trivy's error on stderr, which is what
    the CLI reports; the converters do not run.
    """
    return result.exit_code != 0 and any(
        record.level == "FATAL" and THROTTLED_FATAL_RE.search(record.message)
        for record in records(result.log)
    )


def logs_no_language_files(result: Scan) -> bool:
    """Whether the scan logged that it found no lockfile."""
    return any(is_no_language_files(record) for record in records(result.log))


def is_maven_fetch(record: Record) -> bool:
    """Whether a record is a failed Maven fetch, as the converters count one."""
    fetch = FETCH_FAILURE_RE.match(record.message)
    return fetch is not None and fetch.group(1) == MAVEN_PARSER


def is_throttled_maven_fetch(record: Record) -> bool:
    """Whether a record is a Maven fetch that Maven Central throttled."""
    return is_maven_fetch(record) and THROTTLED_RE.search(record.message) is not None


def is_no_language_files(record: Record) -> bool:
    """Whether a record is trivy finding no lockfile, at a level the modules keep.

    The modules drop DEBUG records but for failed fetches and the first one.
    """
    return (
        record.level != "DEBUG" and NO_LANG_FILES_RE.match(record.message) is not None
    )


if __name__ == "__main__":
    main()
