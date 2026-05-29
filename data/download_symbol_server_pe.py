from isal import igzip as gzip
from datetime import datetime
from struct import unpack
from pathlib import Path
import concurrent.futures
import tempfile
import requests
import orjson
import signify.exceptions
import shutil
import json
import time

from symbol_server_link_enumerate import (
    ServerTooManyRetries,
    write_to_gzip_file,
    get_file_hashes_of_updates,
    make_symbol_server_url,
    create_symbol_server_urllib_session,
)
from upd03_parse_manifests import hash_sum, get_file_version_info, get_file_signing_times
from upd05_group_by_filename import get_file_info_type
import config


def download_pe(session, url, dest_path):
    with session.get(url, stream=True, timeout=60, allow_redirects=True) as response:
        response.raise_for_status()
        with open(dest_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                f.write(chunk)


def download_pe_with_retries(session, url, dest_path, hash, name):
    started_time = time.time()
    sleep_time = 1
    while True:
        try:
            download_pe(session, url, dest_path)
            return True
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            if status is not None and 400 <= status < 500:
                # Permanent: the file isn't served at this URL (e.g. 404). Don't
                # retry, just skip this entry.
                print(f'HTTP {status} for {hash} ({name}), skipping')
                return False
            print(e)
        except Exception as e:
            print(e)

        if time.time() - started_time > 60 * 30:
            raise ServerTooManyRetries(f'Giving up on {hash} ({name}) after 30 minutes of retries')
        time.sleep(sleep_time)
        sleep_time = min(sleep_time * 2, 60 * 5)
        print(f'Retrying {hash}')


def extract_pe_file_info(file_path):
    size = file_path.stat().st_size
    md5, sha1, sha256 = hash_sum(file_path)

    result = {
        'size': size,
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256,
    }

    is_pe_file = False
    if size >= 0x40:
        with open(file_path, 'rb') as handle:
            if handle.read(2) == b'MZ':
                handle.seek(0x3c)
                offset = unpack('<I', handle.read(4))[0]
                if size >= offset + 0x54:
                    handle.seek(offset)
                    if handle.read(4) == b'PE\0\0':
                        is_pe_file = True
                        result['machineType'] = unpack('<H', handle.read(2))[0]
                        handle.seek(offset + 8)
                        result['timestamp'] = unpack('<I', handle.read(4))[0]
                        handle.seek(offset + 0x50)
                        result['virtualSize'] = unpack('<I', handle.read(4))[0]

    if is_pe_file:
        version_info = get_file_version_info(file_path, ['FileVersion', 'FileDescription'])

        if version_info.get('FileVersion'):
            result['version'] = version_info['FileVersion']

        if version_info.get('FileDescription'):
            result['description'] = version_info['FileDescription']

        try:
            signing_times = get_file_signing_times(file_path)
            result['signingStatus'] = 'Unknown'
            result['signatureType'] = 'Overlay'
            result['signingDate'] = signing_times
        except signify.exceptions.SignedPEParseError as e:
            if str(e) != 'The PE file does not contain a certificate table.':
                raise
            result['signingStatus'] = 'Unsigned'

    return result


# Number of concurrent symbol-server downloads. Lower than the HEAD-only
# enumeration (these are full multi-MB GETs, so bandwidth-bound).
DOWNLOAD_CONNECTIONS = 16
# Process in chunks so progress/time-budget is checked and gz files are flushed
# periodically. Items are sorted by filename, so a chunk spans few filenames.
CHUNK_SIZE = 64


def get_pe_info_from_symbol_server(session, name, hash, file_info):
    # Worker: download + extract + verify for a single delta+ entry. Returns the
    # reconstructed full 'pe' fileInfo, or None to skip. No shared state is
    # mutated, so this is safe to run concurrently.
    assert get_file_info_type(file_info) == 'delta+', file_info

    url = make_symbol_server_url(name, file_info['timestamp'], file_info['virtualSize'])

    tempdir = Path(tempfile.mkdtemp(prefix='winbindex_pe_'))
    try:
        dest_path = tempdir / name
        if not download_pe_with_retries(session, url, dest_path, hash, name):
            return None

        new_file_info = extract_pe_file_info(dest_path)

        if 'machineType' not in new_file_info:
            print(f'Downloaded file is not a recognized PE for {hash} ({name})')
            return None

        key = hash.lower()
        hash_key = 'sha256' if len(key) == 64 else 'sha1' if len(key) == 40 else None
        if hash_key is None or new_file_info[hash_key].lower() != key:
            print(f'Hash mismatch for {hash} ({name}): got {new_file_info.get("sha256")}')
            return None

        if (new_file_info['timestamp'] != file_info['timestamp'] or
                new_file_info['virtualSize'] != file_info['virtualSize'] or
                new_file_info['machineType'] != file_info['machineType']):
            print(f'PE header does not match delta-derived values for {hash} ({name})')
            return None

        assert get_file_info_type(new_file_info) in ('vt_or_file', 'file_unknown_sig'), new_file_info

        return new_file_info
    finally:
        shutil.rmtree(tempdir, ignore_errors=True)


def get_pe_info_for_files(names_and_hashes, session, time_to_stop):
    result = {
        'found': set(),
        'not_found': set(),
        'next': None,
        'too_many_retries': False,
    }

    data_cache = {}   # name -> loaded gz dict
    modified = set()  # names with applied changes pending a write

    def load(name):
        if name not in data_cache:
            with gzip.open(config.compressed_filename_path(name), 'rb') as f:
                data_cache[name] = orjson.loads(f.read())
        return data_cache[name]

    def flush(name):
        if name in modified:
            write_to_gzip_file(config.compressed_filename_path(name), orjson.dumps(data_cache[name]))
            modified.discard(name)
        data_cache.pop(name, None)

    count = 0
    index = 0
    total = len(names_and_hashes)
    stop = False
    while index < total and not stop:
        if time_to_stop and datetime.now() >= time_to_stop:
            result['next'] = tuple(names_and_hashes[index])
            break

        chunk = names_and_hashes[index:index + CHUNK_SIZE]
        for name, hash in chunk:
            load(name)

        # Download + extract concurrently; workers don't touch data_cache.
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=DOWNLOAD_CONNECTIONS) as executor:
            future_to_item = {
                executor.submit(get_pe_info_from_symbol_server, session, name, hash,
                                data_cache[name][hash]['fileInfo']): (name, hash)
                for name, hash in chunk
            }
            for future in concurrent.futures.as_completed(future_to_item):
                name, hash = future_to_item[future]
                try:
                    results[(name, hash)] = future.result()
                except ServerTooManyRetries as e:
                    print(e)
                    results[(name, hash)] = ServerTooManyRetries

        # Apply results on the main thread (no concurrent dict mutation).
        for name, hash in chunk:
            r = results.get((name, hash))
            if r is ServerTooManyRetries:
                result['next'] = (name, hash)
                result['too_many_retries'] = True
                stop = True
                break
            if r:
                data_cache[name][hash]['fileInfo'] = r
                modified.add(name)
                result['found'].add((name, hash))
            else:
                result['not_found'].add((name, hash))

        count += len(chunk)
        if config.verbose_progress:
            print(f'Processed {count} of {total}')

        if not stop:
            remaining = {nm for nm, _ in names_and_hashes[index + CHUNK_SIZE:]}
            for nm in [nm for nm in data_cache if nm not in remaining]:
                flush(nm)

        index += CHUNK_SIZE

    for nm in list(data_cache):
        flush(nm)

    return result


def main(time_to_stop=None):
    info_sources_path = config.out_path.joinpath('info_sources.json')
    if info_sources_path.is_file():
        with open(info_sources_path, 'r') as f:
            info_sources = json.load(f)
    else:
        info_sources = {}

    info_progress_path = config.out_path.joinpath('info_progress_symbol_server_download.json')
    if info_progress_path.is_file():
        with open(info_progress_path, 'r') as f:
            info_progress = json.load(f)
    else:
        info_progress = {}

    progress_updates = info_progress.get('updates')
    progress_next = info_progress.get('next')
    if progress_next is not None:
        progress_next = tuple(progress_next)

    if progress_updates == []:
        return None

    names_and_hashes = []
    for name in info_sources.keys():
        file_hashes = set(hash for hash in info_sources[name] if info_sources[name][hash] == 'delta+')
        if not file_hashes:
            continue

        if progress_updates is not None:
            file_hashes &= get_file_hashes_of_updates(name, progress_updates)

        names_and_hashes += [(name, hash) for hash in file_hashes]

    names_and_hashes.sort()

    if progress_next is not None:
        progress_hash_index = names_and_hashes.index(progress_next)
        names_and_hashes = names_and_hashes[progress_hash_index:]

    if config.verbose_progress:
        print(f'{len(names_and_hashes)} items to process')

    session = create_symbol_server_urllib_session()

    result = get_pe_info_for_files(names_and_hashes, session, time_to_stop)

    if result['next'] is None:
        info_progress['next'] = None
        info_progress['updates'] = []
    else:
        info_progress['next'] = result['next']

    for name, hash in result['found']:
        assert info_sources[name][hash] == 'delta+'
        info_sources[name][hash] = 'pe'

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f, indent=0, sort_keys=True)

    with open(info_progress_path, 'w') as f:
        json.dump(info_progress, f, indent=0, sort_keys=True)

    return len(result['found']), result['too_many_retries']


if __name__ == '__main__':
    main()
