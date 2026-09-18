"""Stage raw-refs: raw content reference scan for files outside the structured
per-format routing in remote-refs.

`remote_refs.route()` only handles PDF/RTF/OOXML/ODF/OLE/HTML/EMAIL/IMAGE/CSV/
XML/ARCHIVE and returns [] for everything else (Bucket.OTHER and
Bucket.SPECIALIZED) -- which is where plain text (.txt, .url, ...) and
binary media containers (mp3, m4b, mkv, mp4, and the rest of
SPECIALIZED_EXTENSIONS) end up, since none of them have a dedicated
per-format parser in this project yet. This stage is a deliberately simple
fallback for exactly that gap: a raw-bytes regex scan, reusing the same
URL/FTP/UNC detection already used by remote-refs.

Large media files are not read in full: tag/atom metadata realistically
lives at the head or tail of the container, not scattered through the raw
audio/video payload, so only the first and last HEAD_TAIL_CHUNK bytes are
scanned for files above SMALL_FILE_THRESHOLD. This keeps a multi-GB mkv/mp4
scan bounded instead of reading gigabytes into memory per file.
"""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from canary_scan.lib.config import Bucket, Severity
from canary_scan.lib.io import write_jsonl
from canary_scan.lib.models import FileRecord, Finding, make_info_finding
from canary_scan.lib.runners import RunLogger
from canary_scan.scanners.remote_refs import _scan_raw_text

SMALL_FILE_THRESHOLD = 20 * 1024 * 1024  # files at or below this size are read in full
HEAD_TAIL_CHUNK = 5 * 1024 * 1024  # bytes read from each end of larger files


def _read_scan_regions(path: str) -> str:
    """Read the whole file (small files) or just head+tail chunks (large
    files), decoded permissively so embedded ASCII URLs can still be found
    inside otherwise-binary content."""
    try:
        p = Path(path)
        size = p.stat().st_size
        if size == 0:
            return ""
        with open(path, "rb") as f:
            if size <= SMALL_FILE_THRESHOLD:
                raw = f.read()
            else:
                head = f.read(HEAD_TAIL_CHUNK)
                f.seek(max(size - HEAD_TAIL_CHUNK, 0))
                tail = f.read(HEAD_TAIL_CHUNK)
                raw = head + tail
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _process_raw_refs_record(rec: FileRecord, logger: RunLogger) -> list[Finding]:
    try:
        text = _read_scan_regions(rec.path)
        if not text:
            return []
        return _scan_raw_text(
            rec,
            text,
            tool="raw-refs",
            subcategory="raw_content",
            severity=Severity.HIGH,
            confidence=0.6,
        )
    except Exception as e:
        logger.log(f"Stage raw-refs: error on {rec.path}: {e}")
        return [make_info_finding(rec, "raw-refs", f"raw-refs stage error: {e}")]


def run(
    records: list[FileRecord],
    outdir: Path,
    logger: RunLogger,
    workers: int = 4,
) -> list[Finding]:
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeRemainingColumn

    findings: list[Finding] = []
    # Only files remote-refs' structured routing does not already cover.
    target_records = [rec for rec in records if Bucket(rec.bucket) in (Bucket.OTHER, Bucket.SPECIALIZED)]

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_process_raw_refs_record, rec, logger) for rec in target_records]
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("Scanning raw content (unrouted file types)...", total=len(target_records))
            for future in futures:
                try:
                    findings.extend(future.result())
                except Exception as e:
                    logger.log(f"Stage raw-refs: future error: {e}")
                progress.advance(task)

    write_jsonl(findings, outdir / "canary-scan-raw-refs.json")
    logger.log(f"Stage raw-refs: {len(findings)} findings across {len(target_records)} unrouted files")
    return findings
