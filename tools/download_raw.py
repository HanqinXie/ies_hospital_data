#!/usr/bin/env python3
"""Download public raw-data volumes and verify their recorded size and SHA-256.

No authentication or credential helper is used. Three retries means at most
four HTTP attempts. Existing mismatched files and preexisting .partial files
are never overwritten. --verify-only performs no network requests.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import (
    HTTPRedirectHandler, ProxyHandler, Request, build_opener,
)

RELEASE_BASE = (
    "https://github.com/HanqinXie/ies_hospital_data/releases/download/"
    "raw-data-20261110/"
)
DEFAULT_INDEX = Path(__file__).resolve().parents[1] / "catalog" / "ASSETS.json"
OBJECT_HOSTS = {
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com",
}
WINDOWS_DEVICES = {"CON", "PRN", "AUX", "NUL"} | {
    prefix + str(i) for prefix in ("COM", "LPT") for i in range(1, 10)
}
CHUNK_BYTES = 1024 * 1024


class DownloadError(RuntimeError):
    """A volume was not downloaded or could not be verified."""


def validate_name(name):
    if (
        not isinstance(name, str) or not name or name in (".", "..")
        or ".." in name or any(c in name for c in '/\\<>:"|?*')
        or any(ord(c) < 32 for c in name) or name[-1] in " ."
        or name.split(".", 1)[0].upper() in WINDOWS_DEVICES
        or name.casefold().endswith(".partial")
    ):
        raise ValueError("Unsafe asset name: %r" % (name,))
    return name


def validate_download_url(url, *, redirect=False, allow_local_http=False,
                          asset_name=None):
    """Validate every initial URL and redirect; loopback is library-test only."""
    if not isinstance(url, str) or any(c.isspace() or ord(c) < 32 for c in url):
        raise ValueError("A valid public HTTPS URL is required")
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port") from exc
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("Credentials and fragments are not allowed in URLs")
    host = parsed.hostname
    if (
        allow_local_http and parsed.scheme == "http"
        and host in ("127.0.0.1", "::1", "localhost")
    ):
        return url
    if parsed.scheme != "https" or port not in (None, 443):
        raise ValueError("Only public HTTPS release downloads are allowed")
    if redirect and host in OBJECT_HOSTS:
        if not parsed.path.startswith("/") or "\\" in unquote(parsed.path):
            raise ValueError("Invalid GitHub object path")
        return url
    if host != "github.com":
        raise ValueError("Download host is not an allowed GitHub release host")
    parts = unquote(parsed.path).split("/")
    expected = ["", "HanqinXie", "ies_hospital_data", "releases", "download",
                "raw-data-20261110"]
    if len(parts) != 7 or parts[:6] != expected:
        raise ValueError("URL must name this repository's raw-data-20261110 release")
    validate_name(parts[-1])
    if asset_name is not None and parts[-1] != asset_name:
        raise ValueError("Download URL filename differs from the asset name")
    return url


def validate_asset(asset, *, allow_local_http=False):
    if not isinstance(asset, dict):
        raise ValueError("Each asset must be an object")
    name = validate_name(asset.get("name"))
    size = asset.get("bytes")
    digest = asset.get("sha256")
    if type(size) is not int or size < 0:
        raise ValueError("Asset bytes must be a nonnegative integer")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
        raise ValueError("Asset sha256 must contain exactly 64 hexadecimal characters")
    url = asset.get("download_url", RELEASE_BASE + quote(name, safe=""))
    validate_download_url(url, allow_local_http=allow_local_http, asset_name=name)
    return {"name": name, "bytes": size, "sha256": digest.lower(),
            "download_url": url}


def load_index(path=DEFAULT_INDEX):
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("assets"), list):
        raise ValueError("Index must contain an assets array")
    assets = [validate_asset(asset) for asset in data["assets"]]
    names = set()
    for asset in assets:
        key = asset["name"].casefold()
        if key in names:
            raise ValueError("Duplicate asset name: " + asset["name"])
        names.add(key)
    return assets


def _file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_asset(asset, destination):
    asset = validate_asset(asset)
    target = Path(destination) / asset["name"]
    if target.is_symlink() or not target.is_file():
        raise DownloadError("Missing or unsafe existing file: " + str(target))
    if target.stat().st_size != asset["bytes"] or _file_sha256(target) != asset["sha256"]:
        raise DownloadError("Existing file does not match size/SHA-256: " + str(target))
    return target


class _ReleaseRedirects(HTTPRedirectHandler):
    def __init__(self, asset_name, allow_local_http):
        super().__init__()
        self.asset_name = asset_name
        self.allow_local_http = allow_local_http

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_download_url(
            newurl, redirect=True, allow_local_http=self.allow_local_http,
            asset_name=self.asset_name,
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _temporary_network_error(exc):
    if isinstance(exc, HTTPError):
        return exc.code == 429 or 500 <= exc.code <= 599
    if isinstance(exc, URLError):
        return not isinstance(exc.reason, ssl.SSLCertVerificationError)
    return isinstance(exc, (TimeoutError, socket.timeout, ConnectionError,
                            http.client.IncompleteRead))


def _publish_without_overwrite(partial, target):
    if os.name == "nt":
        # Windows rename is atomic and raises if the destination already exists.
        os.rename(partial, target)
    else:
        # POSIX rename overwrites: link+unlink provides atomic no-clobber publish.
        os.link(partial, target)
        partial.unlink()


def download_asset(asset, destination, *, allow_local_http=False, retries=3,
                   retry_delay=1.0, timeout=60.0):
    """Download one volume; explicit loopback HTTP is reserved for local tests."""
    asset = validate_asset(asset, allow_local_http=allow_local_http)
    if type(retries) is not int or not 0 <= retries <= 3:
        raise ValueError("Retries must be between zero and three")
    destination = Path(destination).resolve()
    target = destination / asset["name"]
    if target.is_symlink() or target.exists():
        # Verify without revalidating test-only URLs; no network is contacted.
        if target.is_symlink() or not target.is_file():
            raise DownloadError("Existing target is not a regular file: " + str(target))
        if target.stat().st_size != asset["bytes"] or _file_sha256(target) != asset["sha256"]:
            raise DownloadError("Existing file does not match size/SHA-256: " + str(target))
        return "verified"
    destination.mkdir(parents=True, exist_ok=True)
    partial = destination / (asset["name"] + ".partial")
    if partial.is_symlink() or partial.exists():
        raise DownloadError("Preexisting partial file must be moved aside: " + str(partial))
    # Disable environment proxies and install no auth/cookie/credential handlers.
    opener = build_opener(ProxyHandler({}), _ReleaseRedirects(
        asset["name"], allow_local_http,
    ))
    for attempt in range(retries + 1):
        created = False
        try:
            with partial.open("xb") as stream:
                created = True
                request = Request(asset["download_url"], headers={
                    "User-Agent": "ies-hospital-public-raw-downloader/1",
                })
                digest = hashlib.sha256()
                count = 0
                with opener.open(request, timeout=timeout) as response:
                    validate_download_url(
                        response.geturl(), redirect=True,
                        allow_local_http=allow_local_http, asset_name=asset["name"],
                    )
                    while True:
                        block = response.read(CHUNK_BYTES)
                        if not block:
                            break
                        count += len(block)
                        if count > asset["bytes"]:
                            raise DownloadError("Downloaded file exceeds recorded size")
                        digest.update(block)
                        stream.write(block)
                if count != asset["bytes"] or digest.hexdigest() != asset["sha256"]:
                    raise DownloadError("Downloaded file fails size/SHA-256: " + asset["name"])
                stream.flush()
                os.fsync(stream.fileno())
            _publish_without_overwrite(partial, target)
            return "downloaded"
        except BaseException as exc:
            if created and partial.exists():
                partial.unlink()
            transient = _temporary_network_error(exc)
            if isinstance(exc, HTTPError):
                exc.close()
            if transient and attempt < retries:
                time.sleep(retry_delay * (2 ** attempt))
                continue
            if isinstance(exc, (KeyboardInterrupt, SystemExit, ValueError, DownloadError)):
                raise
            raise DownloadError("Download failed for %s: %s" % (asset["name"], exc)) from exc
    raise DownloadError("Retry limit exhausted")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        assets = load_index(args.index)
        for asset in assets:
            if args.verify_only:
                verify_asset(asset, args.destination)
                status = "verified"
            else:
                status = download_asset(asset, args.destination)
            print("%s: %s" % (status, asset["name"]))
        return 0
    except (OSError, ValueError, DownloadError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
