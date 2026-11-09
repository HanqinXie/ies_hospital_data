"""Verify or safely restore independent raw ZIP assets; Python standard library only.

The manifest is the restore map. Assets must be downloaded separately into one
directory. No network, model, training or original-source access is performed.
"""
import argparse
from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import time
import zipfile

BLOCK = 1024 * 1024
MAX_ASSET_BYTES = 400_000_000
MAX_FRAGMENT_BYTES = 256 * 1024 * 1024
FORBIDDEN_SUFFIXES = {
    ".md", ".markdown", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff",
    ".svg", ".webp", ".ico", ".fig", ".emf", ".wmf", ".idf", ".epw", ".eso",
    ".mtr", ".sql", ".eio", ".bnd",
}
RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10))}


class RawError(Exception):
    """A safe, content-free refusal or validation failure."""


SECRET_PATTERNS = [
    ("github_classic_token", re.compile(rb"ghp_[A-Za-z0-9]{36}")),
    ("github_fine_grained_token", re.compile(rb"github_pat_[A-Za-z0-9_]{50,}")),
    ("aws_access_key_id", re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}")),
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
]
WLS_PATTERN = re.compile(rb'''(?i)\bWLSSECRET\b["'\s]*[:=]\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([A-Za-z0-9_/\-]+))''')


class SecretScanner:
    def __init__(self):
        self.carry = b""

    def update(self, block):
        data = self.carry + block
        for category, pattern in SECRET_PATTERNS:
            if pattern.search(data):
                raise RawError("High-confidence secret pattern detected: " + category)
        for match in WLS_PATTERN.finditer(data):
            quoted = match.group(1) if match.group(1) is not None else match.group(2)
            value = quoted if quoted is not None else match.group(3)
            if value and (quoted is not None or value.lower() not in {b"null", b"none", b"false"}):
                raise RawError("High-confidence secret pattern detected: gurobi_wls_secret")
        self.carry = data[-4096:]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def emit(event, **fields):
    print(json.dumps(dict(event=event, **fields), ensure_ascii=False), flush=True)


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".writing")
    with open(temp, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def digest_file(path):
    result = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            block = stream.read(BLOCK)
            if not block:
                break
            result.update(block)
    return result.hexdigest()


def valid_sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def safe_logical(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value or ":" in value:
        raise RawError("Unsafe logical path")
    path = PurePosixPath(value)
    if path.is_absolute() or value.startswith("/") or str(path) != value:
        raise RawError("Unsafe or noncanonical logical path")
    for part in path.parts:
        if part in {".", "..", ""} or part[-1:] in {".", " "}:
            raise RawError("Unsafe logical path component")
        if part.split(".", 1)[0].upper() in RESERVED:
            raise RawError("Reserved filename in logical path")
    return path


def check_data_name(value):
    name = str(value).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    if Path(name).suffix.lower() in FORBIDDEN_SUFFIXES or "8760" in name.casefold():
        raise RawError("Excluded document, image, EnergyPlus or annual-data filename")
    if name.casefold() in {"gurobi.lic", ".env", "credentials", "credentials.json", "id_rsa", "id_ed25519"}:
        raise RawError("Credential or license filename is outside the approved scope")


def asset_name(value):
    safe_logical(value)
    if "/" in value or not value.endswith(".zip"):
        raise RawError("Asset must be a ZIP basename")
    return value


def nonnegative(value, label):
    if type(value) is not int or value < 0:
        raise RawError("Invalid nonnegative integer: " + label)
    return value


def validate_manifest(manifest):
    if manifest.get("schema") != "hospital-ies.raw-manifest.v1":
        raise RawError("Unsupported raw manifest schema")
    assets = {}
    expected_members = {}
    for item in manifest.get("assets", []):
        name = asset_name(item["name"])
        if name in assets or not valid_sha(item.get("sha256")):
            raise RawError("Duplicate asset or invalid asset digest")
        length = nonnegative(item.get("bytes"), "asset bytes")
        if length > MAX_ASSET_BYTES:
            raise RawError("Asset exceeds the decimal 400 MB limit")
        assets[name] = item
        expected_members[name] = {}
    if not assets or not isinstance(manifest.get("files"), list) or not manifest["files"]:
        raise RawError("Manifest must contain source files and assets")
    logicals = set()
    ids = set()
    total = 0
    for file in manifest["files"]:
        if file.get("id") in ids:
            raise RawError("Duplicate file ID")
        ids.add(file.get("id"))
        size = nonnegative(file.get("bytes"), "file bytes")
        nonnegative(file.get("mtime_ns"), "file mtime_ns")
        if not valid_sha(file.get("sha256")):
            raise RawError("Invalid source digest")
        paths = file.get("archive_paths", [file["archive_path"]])
        if not paths or file["archive_path"] not in paths:
            raise RawError("Missing primary logical path")
        for path in paths:
            safe_logical(path); check_data_name(path)
            key = path.casefold()
            if key in logicals:
                raise RawError("Duplicate case-insensitive logical path")
            logicals.add(key)
        offset = 0
        if not file.get("fragments"):
            raise RawError("Missing source fragments")
        for fragment in file["fragments"]:
            if fragment.get("offset") != offset:
                raise RawError("Fragment offsets are not contiguous")
            length = nonnegative(fragment.get("bytes"), "fragment bytes")
            if length > MAX_FRAGMENT_BYTES or not valid_sha(fragment.get("sha256")):
                raise RawError("Invalid fragment length or digest")
            asset = asset_name(fragment["asset"])
            member = str(safe_logical(fragment["member"]))
            if asset not in assets or member in expected_members[asset]:
                raise RawError("Unknown asset or duplicate ZIP member mapping")
            expected_members[asset][member] = length
            offset += length
        if offset != size:
            raise RawError("Fragment lengths do not equal original file length")
        total += size
    for logical in logicals:
        parts = logical.split("/")
        if any("/".join(parts[:i]) in logicals for i in range(1, len(parts))):
            raise RawError("Logical file conflicts with a logical parent directory")
    if total != manifest.get("original_total_bytes"):
        raise RawError("Manifest total source bytes mismatch")
    return assets, expected_members


def reject_reparse(path):
    if path.is_symlink():
        raise RawError("Symbolic-link destination is not allowed")
    if path.exists():
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024):
            raise RawError("Reparse-point destination is not allowed")


def contained_target(destination, logical):
    relative = safe_logical(logical)
    target = destination.joinpath(*relative.parts)
    for item in [destination, *list(target.parents)[:len(relative.parts)], target]:
        reject_reparse(item)
    if os.path.commonpath([str(destination), str(target.resolve())]) != str(destination):
        raise RawError("Restore target escapes the destination")
    return target


def publish_no_clobber(temporary, target):
    """Publish a same-filesystem temporary file without replacing a racer.

    Windows rename refuses an existing destination. POSIX rename may replace,
    so an atomic hard-link creation is used there and the temporary link is
    removed only after publication succeeds.
    """
    if os.name == "nt":
        os.rename(temporary, target)
    else:
        os.link(temporary, target, follow_symlinks=False)
        os.unlink(temporary)


class ZipCache:
    def __init__(self, root, limit=8):
        self.root = root
        self.limit = limit
        self.items = OrderedDict()

    def get(self, name):
        if name in self.items:
            value = self.items.pop(name)
            self.items[name] = value
            return value
        value = zipfile.ZipFile(self.root / name)
        self.items[name] = value
        if len(self.items) > self.limit:
            self.items.popitem(last=False)[1].close()
        return value

    def close(self):
        for value in self.items.values():
            value.close()


def run(manifest_path, assets_path, destination=None, verify_only=False, report=None):
    started = time.monotonic()
    verifier_sha256 = digest_file(Path(__file__))
    manifest_path, assets_path = Path(manifest_path), Path(assets_path).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    assets, expected_members = validate_manifest(manifest)
    # Every asset and central directory is authenticated before restore writes.
    for index, (name, item) in enumerate(assets.items(), 1):
        path = assets_path / name
        reject_reparse(path)
        if not path.is_file() or path.stat().st_size != item["bytes"] or digest_file(path) != item["sha256"]:
            raise RawError("Asset length or SHA256 mismatch: " + name)
        with zipfile.ZipFile(path) as archive:
            seen = {}
            for info in archive.infolist():
                safe_logical(info.filename)
                if info.is_dir() or info.filename in seen or stat.S_ISLNK(info.external_attr >> 16):
                    raise RawError("Unexpected directory, duplicate or symlink ZIP member")
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise RawError("Unsupported member compression")
                seen[info.filename] = info.file_size
            if seen != expected_members[name]:
                raise RawError("ZIP central directory differs from manifest: " + name)
        if index == len(assets) or index % 10 == 0:
            emit("assets_verified", count=index, total=len(assets))
    root = None
    targets = {}
    if not verify_only:
        if destination is None:
            raise RawError("Restore requires --destination")
        supplied = Path(destination).absolute()
        for parent in [supplied, *supplied.parents]:
            reject_reparse(parent)
        root = supplied.resolve()
        for file in manifest["files"]:
            file_targets = []
            for logical in file.get("archive_paths", [file["archive_path"]]):
                target = contained_target(root, logical)
                if target.exists() and (not target.is_file() or target.stat().st_size != file["bytes"]
                                        or digest_file(target) != file["sha256"]):
                    raise RawError("Existing inconsistent destination file will not be overwritten")
                file_targets.append(target)
            targets[file["id"]] = file_targets
        required = sum(file["bytes"] * sum(not p.exists() for p in targets[file["id"]])
                       for file in manifest["files"])
        ancestor = root
        while not ancestor.exists():
            ancestor = ancestor.parent
        if shutil.disk_usage(ancestor).free < required:
            raise RawError("Insufficient free space for the requested full restore")
        root.mkdir(parents=True, exist_ok=True)
    cache = ZipCache(assets_path)
    count = 0
    restored = 0
    fragments = 0
    try:
        for file in manifest["files"]:
            source_digest = hashlib.sha256()
            scanner = SecretScanner()
            output = None
            temporary = None
            missing = [] if verify_only else [p for p in targets[file["id"]] if not p.exists()]
            if missing:
                primary = missing[0]
                primary.parent.mkdir(parents=True, exist_ok=True)
                contained_target(root, str(primary.relative_to(root)).replace(os.sep, "/"))
                temporary = primary.with_name(primary.name + ".raw-restoring")
                if temporary.exists():
                    raise RawError("Restore temporary file already exists")
                output = open(temporary, "xb")
            try:
                for fragment in file["fragments"]:
                    chunk_digest = hashlib.sha256()
                    length = 0
                    with cache.get(fragment["asset"]).open(fragment["member"]) as source:
                        while True:
                            block = source.read(BLOCK)
                            if not block:
                                break
                            length += len(block)
                            if length > fragment["bytes"]:
                                raise RawError("Fragment expands beyond its declared length")
                            scanner.update(block)
                            chunk_digest.update(block); source_digest.update(block)
                            if output:
                                output.write(block)
                    if length != fragment["bytes"] or chunk_digest.hexdigest() != fragment["sha256"]:
                        raise RawError("Fragment length or SHA256 mismatch")
                    fragments += 1
                if source_digest.hexdigest() != file["sha256"]:
                    raise RawError("Reassembled original-file SHA256 mismatch")
                if output:
                    output.flush(); os.fsync(output.fileno()); output.close(); output = None
                    primary = missing[0]
                    if primary.exists():
                        raise RawError("Restore destination appeared during streaming")
                    publish_no_clobber(temporary, primary)
                    os.utime(primary, ns=(file["mtime_ns"], file["mtime_ns"]))
                    restored += 1
                    for alias in missing[1:]:
                        contained_target(root, str(alias.relative_to(root)).replace(os.sep, "/"))
                        alias.parent.mkdir(parents=True, exist_ok=True)
                        with open(primary, "rb") as src, open(alias, "xb") as dst:
                            shutil.copyfileobj(src, dst, BLOCK)
                        os.utime(alias, ns=(file["mtime_ns"], file["mtime_ns"]))
                        restored += 1
                count += 1
                if count == len(manifest["files"]) or count % 100 == 0:
                    emit("files_verified", count=count, total=len(manifest["files"]))
            finally:
                if output:
                    output.close()
    finally:
        cache.close()
    if digest_file(Path(__file__)) != verifier_sha256:
        raise RawError("Verifier tool changed during verification")
    result = dict(schema="hospital-ies.packaging-verification.v1", status="passed", created_utc=utc_now(),
                  mode="verify-only" if verify_only else "restore", manifest_sha256=digest_file(manifest_path),
                  verifier_tool_sha256=verifier_sha256,
                  source_files=count, fragments=fragments, assets=len(assets),
                  original_bytes=manifest["original_total_bytes"],
                  asset_bytes=sum(a["bytes"] for a in assets.values()),
                  restored_logical_files=restored, elapsed_seconds=round(time.monotonic() - started, 3),
                  checks=dict(asset_sha256=True, fragment_sha256=True, reconstructed_file_sha256=True,
                              plaintext_secret_scan=True, archive_paths_contained=True,
                              asset_limit_bytes=MAX_ASSET_BYTES))
    if report:
        atomic_json(report, result)
    emit("verification_complete", **result)
    return result


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--assets", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify-only", action="store_true")
    mode.add_argument("--destination")
    parser.add_argument("--report")
    args = parser.parse_args()
    try:
        run(args.manifest, args.assets, args.destination, args.verify_only, args.report)
    except (RawError, OSError, ValueError, KeyError, zipfile.BadZipFile, RuntimeError) as error:
        # Messages contain filenames or validation categories, never source payload.
        message = str(error) if isinstance(error, RawError) else type(error).__name__
        result = dict(schema="hospital-ies.packaging-verification.v1", status="failed",
                      created_utc=utc_now(), reason=message)
        if args.report:
            atomic_json(args.report, result)
        emit("verification_failed", **result)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
