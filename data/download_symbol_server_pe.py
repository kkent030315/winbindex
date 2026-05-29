from isal import igzip as gzip
from datetime import datetime
from struct import unpack
from pathlib import Path
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


def get_pe_info_from_symbol_server(session, hash, name, data):
    file_info = data[hash]['fileInfo']

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

        data[hash]['fileInfo'] = new_file_info

        return data
    finally:
        shutil.rmtree(tempdir, ignore_errors=True)


def get_pe_info_for_files(names_and_hashes, session, time_to_stop):
    result = {
        'found': set(),
        'not_found': set(),
        'next': None,
        'too_many_retries': False,
    }

    output_path = None
    data = None
    data_modified = False

    count = 0
    for name, hash in names_and_hashes:
        if time_to_stop and datetime.now() >= time_to_stop:
            result['next'] = (name, hash)
            break

        new_output_path = config.compressed_filename_path(name)
        if new_output_path != output_path:
            if output_path and data_modified:
                write_to_gzip_file(output_path, orjson.dumps(data))

            output_path = config.compressed_filename_path(name)
            with gzip.open(output_path, 'rb') as f:
                data = orjson.loads(f.read())
                data_modified = False

        try:
            new_data = get_pe_info_from_symbol_server(session, hash, name, data)
        except ServerTooManyRetries as e:
            print(e)
            result['next'] = (name, hash)
            result['too_many_retries'] = True
            break

        if new_data:
            data = new_data
            data_modified = True
            result['found'].add((name, hash))
        else:
            result['not_found'].add((name, hash))

        count += 1
        if count % 10 == 0 and config.verbose_progress:
            print(f'Processed {count} of {len(names_and_hashes)}')

    if output_path and data_modified:
        write_to_gzip_file(output_path, orjson.dumps(data))

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
