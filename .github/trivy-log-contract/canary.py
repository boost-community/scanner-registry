"""Fail when the pinned trivy's log stops matching what the converters parse.

The trivy converters read trivy's log, not only its report: a `Failed to fetch`
DEBUG record is their only sign of a throttled Maven Central, and a
`Number of language-specific files` record of a repository with no lockfile.
Both are undocumented trivy wording: reworded, the converters' fetch counts
silently read 0 and the no-lockfile error silently disappears.

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

TRIVY_URL = "https://assets.build.boostsecurity.io/scanners/trivy/trivy-{version}/linux/{arch}/trivy.gz"
ARCHES = {
    "x86_64": ("amd64", "LINUX_X86_64_SHA"),
    "aarch64": ("arm64", "LINUX_ARM64_SHA"),
}
FIXTURE = Path(__file__).parent / "fixture"


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

    checks = (
        ("a failed Maven fetch (FETCH_FAILURE_RE)", unreachable, is_maven_fetch),
        (
            "a throttled Maven fetch (FETCH_FAILURE_RE, THROTTLED_RE)",
            throttled,
            is_throttled_maven_fetch,
        ),
        (
            "no language files (NO_LANG_FILES_RE)",
            no_language_files,
            is_no_language_files,
        ),
    )
    broken = [
        f"{contract}:\n{log}"
        for contract, log, matches in checks
        if not any(matches(record) for record in records(log))
    ]

    if broken:
        sys.exit(
            f"trivy {pin['VERSION']} no longer logs these as the converters in"
            " boostsec-scanner-trivy and boostsec-scanner-trivy-sbom parse them;"
            " update both before bumping trivy.\n\n" + "\n\n".join(broken)
        )

    print(f"trivy {pin['VERSION']}: log matches what the converters parse")


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


def scan(trivy: Path, cert: Path, target: Path) -> str:
    """Scan a directory and return trivy's log.

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
    return result.stderr


def records(log: str) -> list[Record]:
    """Split a log into its records."""
    return [
        Record(level=match.group(1), message=match.group(2))
        for line in log.splitlines()
        if (match := LOG_LINE_RE.match(line))
    ]


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
