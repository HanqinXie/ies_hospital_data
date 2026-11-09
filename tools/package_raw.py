"""Package only exact approved source paths into bounded independent ZIP assets.

No recursive discovery, network, model, training, or source modification is used.
Run --plan-only before packaging. Completed assets are atomically sealed and
listed in assets/PROGRESS.json; catalog files are final only after all sources
have passed their size/mtime checks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time
import zipfile

from restore_raw import (BLOCK, MAX_ASSET_BYTES, MAX_FRAGMENT_BYTES, RawError, atomic_json,
                         check_data_name, digest_file, emit, safe_logical, utc_now,
                         validate_manifest, SecretScanner)


def inspect_original_zip(path):
    with zipfile.ZipFile(path) as archive:
        seen = set()
        for info in archive.infolist():
            logical = info.filename.rstrip("/")
            if not logical:
                continue
            safe_logical(logical); check_data_name(logical)
            if logical.casefold() in seen or stat.S_ISLNK(info.external_attr >> 16):
                raise RawError("Duplicate or symlink member in original ZIP")
            seen.add(logical.casefold())
            if info.flag_bits & 1:
                raise RawError("Encrypted original ZIP is not auditable")
    return len(seen)


def load_sources(scope_paths):
    by_source = {}
    scope_receipts = []
    paths_seen = {}
    for scope_path in scope_paths:
        path = Path(scope_path).resolve()
        raw = path.read_bytes()
        scope = json.loads(raw.decode("utf-8-sig"))
        if not isinstance(scope, list):
            raise RawError("Each scope must be a JSON array")
        scope_receipts.append(dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                                   records=len(scope)))
        for record in scope:
            source = Path(record["source_path"]).absolute()
            key = os.path.normcase(os.path.normpath(str(source)))
            logical = str(safe_logical(record["archive_path"]))
            check_data_name(source.name); check_data_name(logical)
            if logical.casefold() in paths_seen and paths_seen[logical.casefold()] != key:
                raise RawError("Different source paths collide at a logical destination")
            paths_seen[logical.casefold()] = key
            info = source.lstat()
            if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 1024:
                raise RawError("Source must be a regular non-reparse file")
            if info.st_size != record["bytes"]:
                raise RawError("Scope/source length changed: " + logical)
            if key not in by_source:
                by_source[key] = dict(source_path=str(source), archive_path=logical, archive_paths=[],
                                      bytes=info.st_size, mtime_ns=info.st_mtime_ns,
                                      groups=[], roles=[], scope_records=[])
            item = by_source[key]
            if info.st_size != item["bytes"] or info.st_mtime_ns != item["mtime_ns"]:
                raise RawError("Same source changed while merging scope")
            if logical not in item["archive_paths"]:
                item["archive_paths"].append(logical)
            for target, singular in [("groups", "group"), ("roles", "role")]:
                values = list(record.get(target, [])) + ([record[singular]] if singular in record else [])
                for value in values:
                    if value not in item[target]:
                        item[target].append(value)
            item["scope_records"].append(record)
    sources = list(by_source.values())
    if not sources:
        raise RawError("Empty approved source scope")
    logicals = set(paths_seen)
    for logical in logicals:
        parts = logical.split("/")
        if any("/".join(parts[:i]) in logicals for i in range(1, len(parts))):
            raise RawError("Logical file conflicts with a parent path")
    for number, source in enumerate(sources, 1):
        source["id"] = f"f{number:06d}"
    return sources, scope_receipts


def make_plan(sources, scopes, target, chunk, maximum):
    raw = 0
    members = 0
    volumes = []
    for source in sources:
        remaining = source["bytes"]
        lengths = [0] if remaining == 0 else None
        while remaining or lengths:
            length = lengths.pop() if lengths else min(remaining, chunk)
            if raw + length > target and members:
                volumes.append(dict(raw_bytes=raw, members=members)); raw = members = 0
            raw += length; members += 1; remaining -= length
    if members:
        volumes.append(dict(raw_bytes=raw, members=members))
    return dict(schema="hospital-ies.packaging-plan.v1", created_utc=utc_now(),
                source_count=len(sources), logical_path_count=sum(len(s["archive_paths"]) for s in sources),
                original_total_bytes=sum(s["bytes"] for s in sources), estimated_volumes=len(volumes),
                max_asset_bytes=maximum, target_raw_bytes=target, chunk_bytes=chunk,
                volume_raw_plan=volumes, source_scopes=scopes,
                original_zip_count=sum(s["source_path"].lower().endswith(".zip") for s in sources),
                compression="Original ZIP bytes STORE; other sources DEFLATE level 1",
                source_snapshot=[{k:s[k] for k in ["id", "source_path", "bytes", "mtime_ns"]} for s in sources])


def source_stable(source):
    info = Path(source["source_path"]).stat()
    if info.st_size != source["bytes"] or info.st_mtime_ns != source["mtime_ns"]:
        raise RawError("Source size/mtime_ns changed: " + source["archive_path"])


class VolumeWriter:
    def __init__(self, directory, maximum, target, plan_count):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        if any(self.directory.glob("raw-part-*.zip")) or any(self.directory.glob("raw-part-*.building")):
            raise RawError("Asset directory already contains a prior run; use a new work root")
        self.maximum = maximum
        self.target = target
        self.plan_count = plan_count
        self.assets = []
        self.archive = None
        self.raw_bytes = 0
        self.members = 0
        self.started = time.monotonic()

    def open_volume(self):
        self.name = f"raw-part-{len(self.assets) + 1:04d}.zip"
        self.temporary = self.directory / (self.name + ".building")
        self.archive = zipfile.ZipFile(self.temporary, "x", compression=zipfile.ZIP_DEFLATED,
                                       compresslevel=1, allowZip64=True)
        self.raw_bytes = self.members = 0

    def seal(self):
        if self.archive is None:
            return
        self.archive.close(); self.archive = None
        size = self.temporary.stat().st_size
        if size > self.maximum or size > MAX_ASSET_BYTES:
            raise RawError("Sealed ZIP exceeds the asset limit")
        digest = digest_file(self.temporary)
        final = self.directory / self.name
        self.temporary.rename(final)
        receipt = dict(name=self.name, bytes=size, sha256=digest,
                       original_fragment_bytes=self.raw_bytes, members=self.members, sealed=True)
        self.assets.append(receipt)
        atomic_json(self.directory / "PROGRESS.json",
                    dict(schema="hospital-ies.packaging-progress.v1", status="PACKING",
                         created_utc=utc_now(), assets=self.assets,
                         asset_bytes=sum(a["bytes"] for a in self.assets),
                         sealed_original_bytes=sum(a["original_fragment_bytes"] for a in self.assets)))
        emit("volume_sealed", **receipt, completed=len(self.assets), estimated_total=self.plan_count,
             elapsed_seconds=round(time.monotonic() - self.started, 2))

    def add(self, source, stream, length, index, offset, file_hash, scanner):
        if self.archive and self.members and self.raw_bytes + length > self.target:
            self.seal()
        if self.archive is None:
            self.open_volume()
        member = f"fragments/{source['id']}/{index:06d}.bin"
        info = zipfile.ZipInfo(member, date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED if source["source_path"].lower().endswith(".zip") else zipfile.ZIP_DEFLATED
        info._compresslevel = 1
        info.file_size = length
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        fragment_hash = hashlib.sha256()
        remaining = length
        with self.archive.open(info, "w", force_zip64=True) as target:
            while remaining:
                block = stream.read(min(BLOCK, remaining))
                if not block:
                    raise RawError("Source ended before the frozen length")
                scanner.update(block)
                file_hash.update(block); fragment_hash.update(block); target.write(block)
                remaining -= len(block)
        self.raw_bytes += length; self.members += 1
        return dict(offset=offset, bytes=length, sha256=fragment_hash.hexdigest(),
                    asset=self.name, member=member,
                    compression="STORE" if info.compress_type == zipfile.ZIP_STORED else "DEFLATE1")


def package(work, sources, scopes, plan, target, chunk, maximum):
    assets_dir = work / "assets"
    catalog = work / "repo/catalog"
    catalog.mkdir(parents=True, exist_ok=True)
    writer = VolumeWriter(assets_dir, maximum, target, plan["estimated_volumes"])
    files = []
    zip_audits = []
    active = None
    try:
        for source in sources:
            active = source
            source_stable(source)
            if source["source_path"].lower().endswith(".zip"):
                count = inspect_original_zip(source["source_path"])
                zip_audits.append(dict(file_id=source["id"], central_directory_members=count,
                                       forbidden_names=False, nested_payloads_decompressed=False))
            file_hash = hashlib.sha256()
            scanner = SecretScanner()
            fragments = []
            offset = 0
            with open(source["source_path"], "rb") as stream:
                opened = os.fstat(stream.fileno())
                if opened.st_size != source["bytes"] or opened.st_mtime_ns != source["mtime_ns"]:
                    raise RawError("Opened source differs from frozen metadata")
                while offset < source["bytes"] or not fragments:
                    length = min(chunk, source["bytes"] - offset)
                    fragments.append(writer.add(source, stream, length, len(fragments), offset, file_hash, scanner))
                    offset += length
                if stream.read(1):
                    raise RawError("Source grew while packaging")
                closing = os.fstat(stream.fileno())
                if closing.st_size != source["bytes"] or closing.st_mtime_ns != source["mtime_ns"]:
                    raise RawError("Source handle metadata changed while packaging")
            source_stable(source)
            files.append(dict(source, sha256=file_hash.hexdigest(), fragments=fragments))
            if len(files) % 100 == 0:
                emit("sources_packed", completed=len(files), total=len(sources))
        writer.seal()
        for source in sources:
            source_stable(source)
        manifest = dict(schema="hospital-ies.raw-manifest.v1", created_utc=utc_now(),
                        original_total_bytes=sum(s["bytes"] for s in sources), source_count=len(sources),
                        source_scopes=scopes, max_asset_bytes=maximum, target_raw_bytes=target,
                        chunk_bytes=chunk, source_metadata_rechecked=True, source_files_read_only=True,
                        secret_scan="streamed plaintext high-confidence patterns; nested ZIP payloads not decompressed",
                        original_zip_central_directory_audits=zip_audits,
                        assets=writer.assets, files=files)
        validate_manifest(manifest)
        atomic_json(catalog / "RAW_MANIFEST.json", manifest)
        atomic_json(catalog / "ASSETS.json", dict(schema="hospital-ies.raw-assets.v1", created_utc=utc_now(),
                                                 assets=writer.assets,
                                                 original_total_bytes=manifest["original_total_bytes"]))
        atomic_json(assets_dir / "PROGRESS.json", dict(schema="hospital-ies.packaging-progress.v1",
                    status="PACKED_AWAITING_FULL_VERIFICATION", created_utc=utc_now(), assets=writer.assets,
                    source_count=len(files), original_total_bytes=manifest["original_total_bytes"]))
        atomic_json(work / "PACKAGING_RECEIPT.json", dict(schema="hospital-ies.packaging-receipt.v1",
                    status="PACKED_AWAITING_FULL_VERIFICATION", created_utc=utc_now(), source_count=len(files),
                    original_total_bytes=manifest["original_total_bytes"], asset_count=len(writer.assets),
                    asset_total_bytes=sum(a["bytes"] for a in writer.assets), source_size_mtime_recheck=True,
                    manifest_sha256=digest_file(catalog / "RAW_MANIFEST.json")))
        emit("packaging_complete", files=len(files), original_bytes=manifest["original_total_bytes"],
             assets=len(writer.assets), asset_bytes=sum(a["bytes"] for a in writer.assets))
    except Exception as error:
        if writer.archive:
            writer.archive.close()
        reason = str(error) if isinstance(error, RawError) else type(error).__name__
        atomic_json(work / "PACKAGING_FAILURE.json", dict(status="FAILED", created_utc=utc_now(), reason=reason,
                    file_id=active["id"] if active else None,
                    archive_path=active["archive_path"] if active else None, sealed_assets=writer.assets,
                    completed_source_count=len(files)))
        raise


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-root", required=True)
    parser.add_argument("--scope", required=True, action="append")
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--target-raw-bytes", type=int, default=350_000_000)
    parser.add_argument("--chunk-bytes", type=int, default=MAX_FRAGMENT_BYTES)
    parser.add_argument("--max-asset-bytes", type=int, default=MAX_ASSET_BYTES)
    args = parser.parse_args()
    try:
        if not (0 < args.chunk_bytes <= MAX_FRAGMENT_BYTES and args.chunk_bytes <= args.target_raw_bytes
                < args.max_asset_bytes <= MAX_ASSET_BYTES):
            raise RawError("Invalid chunk, target or maximum-byte limits")
        work = Path(args.work_root).resolve()
        work.mkdir(parents=True, exist_ok=True)
        sources, scopes = load_sources(args.scope)
        plan = make_plan(sources, scopes, args.target_raw_bytes, args.chunk_bytes, args.max_asset_bytes)
        atomic_json(work / "PACKAGING_PLAN.json", plan)
        emit("packaging_plan", **{k:v for k,v in plan.items() if k not in {"volume_raw_plan", "source_snapshot", "source_scopes"}})
        if args.plan_only:
            return 0
        if shutil.disk_usage(work).free < plan["original_total_bytes"] + 2_000_000_000:
            raise RawError("Insufficient free space for a conservative raw-size packaging budget")
        package(work, sources, scopes, plan, args.target_raw_bytes, args.chunk_bytes, args.max_asset_bytes)
    except (RawError, OSError, ValueError, KeyError, zipfile.BadZipFile, RuntimeError) as error:
        message = str(error) if isinstance(error, RawError) else type(error).__name__
        emit("packaging_failed", reason=message)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
