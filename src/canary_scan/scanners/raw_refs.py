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
from canary_scan.scanners.remote_refs import FTP_RE, URL_RE, _clean_url

SMALL_FILE_THRESHOLD = 20 * 1024 * 1024  # files at or below this size are read in full
HEAD_TAIL_CHUNK = 5 * 1024 * 1024  # bytes read from each end of larger files


def _truncate_at_binary_noise(s: str) -> str:
    # URL_RE has no upper bound on trailing characters besides whitespace/quotes/brackets,
    # so inside raw ID3/atom binary data it happily swallows the NUL-byte padding and the
    # next frame's ID (e.g. "https://tracker.com/me\x00TDRC...") into the match. A URL
    # never legitimately contains a C0 control character, so cut there. Non-UTF8 binary
    # bytes decode to U+FFFD (the replacement character) rather than a control character,
    # so cut there too -- otherwise two unrelated readable fragments either side of a
    # run of raw binary bytes (frame sizes, flags, ...) can merge into one bogus "URL".
    for i, ch in enumerate(s):
        if ord(ch) < 0x20 or ch == "\ufffd":
            return s[:i]
    return s


def _scan_raw_refs_text(rec: FileRecord, text: str) -> list[Finding]:
    # Deliberately narrower than remote_refs._scan_raw_text: real-world testing against
    # a binary media library showed UNC_RE (\\server\share) matching pure coincidence in
    # compressed audio payload bytes (e.g. "\\k\m", "\\x\.H") -- short, generic-looking
    # "paths" with no relation to an actual network share. Random binary noise can't
    # coincidentally spell "https?://" or "ftp://" (7-8 specific ASCII bytes in a row),
    # but it CAN coincidentally match the much shorter/looser UNC pattern, and worse, the
    # report stage's uniqueness heuristic then treats each distinct piece of noise as a
    # signal (unique-per-file "canary") and escalates it to critical. So UNC detection is
    # intentionally left out of this stage; URL/FTP only.
    findings: list[Finding] = []
    for raw_url in URL_RE.findall(text):
        cleaned, is_canary = _clean_url(_truncate_at_binary_noise(raw_url))
        if not cleaned:
            continue
        if is_canary:
            findings.append(
                Finding.from_file_record(
                    rec, "raw-refs", "active_url", "canarytoken",
                    f"Canarytoken detected: {cleaned}", cleaned, "raw-refs", Severity.CRITICAL, 1.0,
                )
            )
        else:
            findings.append(
                Finding.from_file_record(
                    rec, "raw-refs", "active_url", "raw_content",
                    f"{rec.bucket.upper()} references external URL: {cleaned}", cleaned, "raw-refs",
                    Severity.HIGH, 0.6,
                )
            )
    for raw_ftp in FTP_RE.findall(text):
        ftp = _truncate_at_binary_noise(raw_ftp)
        if not ftp:
            continue
        findings.append(
            Finding.from_file_record(
                rec, "raw-refs", "active_url", "raw_content_ftp",
                f"{rec.bucket.upper()} references external FTP path: {ftp}", ftp, "raw-refs",
                Severity.HIGH, 0.6,
            )
        )
    return findings


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
                # NUL separator: without it, a fragment truncated mid-match at the head
                # cutoff could otherwise merge with whatever the tail happens to start
                # with, producing a bogus "URL" that never existed in the file.
                raw = head + b"\x00" + tail
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _process_raw_refs_record(rec: FileRecord, logger: RunLogger) -> list[Finding]:
    try:
        text = _read_scan_regions(rec.path)
        if not text:
            return []
        return _scan_raw_refs_text(rec, text)
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
