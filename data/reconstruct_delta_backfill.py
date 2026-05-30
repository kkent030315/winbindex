from isal import igzip as gzip
import orjson
import sys
import time
import json
import shutil
import hashlib
import tempfile
import requests
from pathlib import Path

import config
from symbol_server_link_enumerate import write_to_gzip_file
from upd02_get_manifests_from_updates import (
    get_update, get_update_download_urls, extract_update_files,
    UpdateNotFound, UpdateNotSupported,
)
from upd03_parse_manifests import apply_forward_delta, get_pe_file_info, hash_sum


# Backfill stage: reconstruct the exact file for delta+ entries that the
# symbol-server download stage can't resolve (timestamp+SizeOfImage collisions).
# For each such entry it re-fetches the update that shipped the forward delta,
# applies the cached branch baseline (see populate_delta_bases.py), verifies the
# hash, and writes a full 'pe' fileInfo. Wrong base / corrupt delta -> the entry
# is left untouched (never publish unverified data). Heavy work (downloads,
# extraction) is meant to run on a CI runner, not locally.


def is_unresolved_delta(file_info):
    return (file_info
            and 'machineType' in file_info
            and 'signingStatus' not in file_info
            and not file_info.get('version'))


def entry_targets(entry):
    # Yield (windows_version, kb, branch) candidates for an entry, best first.
    seen = []
    for windows_version, updates in entry.get('windowsVersions', {}).items():
        for kb, info in updates.items():
            branch = None
            for assembly in info.get('assemblies', {}).values():
                version = assembly.get('assemblyIdentity', {}).get('version')
                if version and len(version.split('.')) == 4:
                    branch = int(version.split('.')[2])
            if branch is not None:
                seen.append((windows_version, kb, branch))
    return seen


def download_and_extract_update(windows_version, kb, work_dir):
    update_uid, _ = get_update(windows_version, kb)
    download_urls = get_update_download_urls(update_uid)
    matching = [u for u in download_urls if kb.lower() in u.lower()]
    if not matching:
        raise UpdateNotFound
    url = matching[0]

    work_dir.mkdir(parents=True, exist_ok=True)
    local_path = work_dir / url.split('/')[-1]

    # Update packages are large; retry transient network failures.
    last_error = None
    for attempt in range(4):
        try:
            with requests.get(url, stream=True, timeout=180) as response:
                response.raise_for_status()
                with open(local_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        f.write(chunk)
            last_error = None
            break
        except (requests.exceptions.ChunkedEncodingError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as e:
            last_error = e
            print(f'  download retry {attempt + 1} for {kb}: {e}')
            time.sleep(2 ** attempt)
    if last_error is not None:
        raise last_error

    extract_update_files(work_dir, local_path, windows_version)


def reconstruct_entry(name, hash, entry):
    for windows_version, kb, branch in entry_targets(entry):
        base_path = config.delta_base_path(name, branch)
        if not base_path.is_file():
            continue

        # Outside out_path (the gh-pages checkout) so it is never committed.
        work_dir = Path('delta_backfill_work').joinpath(windows_version, kb)
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)
        try:
            try:
                download_and_extract_update(windows_version, kb, work_dir)
            except (UpdateNotFound, UpdateNotSupported):
                continue
            except Exception as e:
                # A flaky download / extraction for one update must not abort the
                # whole backfill; skip this candidate and move on.
                print(f'  skip {kb} ({windows_version}): {e}')
                continue

            deltas = [p for p in work_dir.rglob(name) if p.parent.name == 'f']
            if not deltas:
                continue

            reconstructed = apply_forward_delta(base_path.read_bytes(), deltas[0])
            if reconstructed is None:
                continue
            if hashlib.sha256(reconstructed).hexdigest() != hash:
                continue

            result = {
                'size': len(reconstructed),
                'md5': hashlib.md5(reconstructed).hexdigest(),
                'sha1': hashlib.sha1(reconstructed).hexdigest(),
                'sha256': hashlib.sha256(reconstructed).hexdigest(),
            }
            temp_dir = Path(tempfile.mkdtemp(prefix='winbindex_backfill_'))
            try:
                temp_file = temp_dir / name
                temp_file.write_bytes(reconstructed)
                result.update(get_pe_file_info(temp_file))
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)
            return result
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    return None


def backfill_filename(name, info_sources):
    gz_path = config.compressed_filename_path(name)
    with gzip.open(gz_path, 'rb') as f:
        data = orjson.loads(f.read())

    fixed = 0
    for hash, entry in data.items():
        if info_sources.get(name, {}).get(hash) == 'pe':
            continue
        if not is_unresolved_delta(entry.get('fileInfo')):
            continue
        result = reconstruct_entry(name, hash, entry)
        if result:
            entry['fileInfo'] = result
            info_sources.setdefault(name, {})[hash] = 'pe'
            fixed += 1
            print(f'  reconstructed {hash[:12]} -> {result.get("version")}')

    if fixed:
        write_to_gzip_file(gz_path, orjson.dumps(data))

    return fixed


def main(names=None):
    info_sources_path = config.out_path.joinpath('info_sources.json')
    with open(info_sources_path, 'r') as f:
        info_sources = json.load(f)

    if not names:
        names = sorted(info_sources.keys())

    total = 0
    for name in names:
        if not config.compressed_filename_path(name).is_file():
            continue
        print(f'Backfilling {name}')
        total += backfill_filename(name, info_sources)

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f, indent=0, sort_keys=True)

    print(f'Reconstructed {total} files via delta backfill')
    return total


if __name__ == '__main__':
    main(sys.argv[1:] or None)
