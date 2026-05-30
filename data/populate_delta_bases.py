import argparse
import subprocess
import tempfile
import shutil
import requests
from pathlib import Path

import config


# Populate the delta-reconstruction base catalog.
#
# Files shipped only as forward differentials are reconstructed in
# upd03_parse_manifests / reconstruct_delta_backfill by applying the forward
# delta to the branch's baseline (RTM) file. The baseline bytes can't be fetched
# from the symbol server (timestamp+SizeOfImage collisions), so they're sourced
# once per (file, branch) from install media and cached here at:
#
#   data/delta_bases/<branch>/<name>   (a local runtime cache, gitignored,
#   deliberately outside out_path so it is never committed)
#
# Designed to run on a CI runner (fast network), not a local machine.
#
# Examples:
#   python populate_delta_bases.py --all                       # everything in config.delta_base_media
#   python populate_delta_bases.py --branch 17763 --name ci.dll --iso-url <url>
#   python populate_delta_bases.py --branch 17763 --name ci.dll --wim D:\sources\install.wim
#   python populate_delta_bases.py --branch 17763 --name ci.dll --source C:\rtm\ci.dll


def extract_from_wim(wim_path: Path, name: str, dest: Path):
    temp_dir = Path(tempfile.mkdtemp(prefix='winbindex_wimextract_'))
    try:
        inner = fr'1\Windows\System32\{name}'
        args = ['7z', 'e', str(wim_path), inner, f'-o{temp_dir}', '-y']
        subprocess.check_call(args, stdout=subprocess.DEVNULL)
        extracted = temp_dir / name
        if not extracted.is_file():
            raise Exception(f'{inner} not found in {wim_path}')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(extracted, dest)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def extract_from_iso(iso_url: str, name: str, dest: Path):
    temp_dir = Path(tempfile.mkdtemp(prefix='winbindex_iso_'))
    try:
        iso_path = temp_dir / 'media.iso'
        print(f'Downloading {iso_url}')
        with requests.get(iso_url, stream=True, timeout=300) as response:
            response.raise_for_status()
            with open(iso_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    f.write(chunk)

        # ISO -> sources/install.wim -> Windows\System32\<name>
        subprocess.check_call(['7z', 'e', str(iso_path), 'sources/install.wim',
                               f'-o{temp_dir}', '-y'], stdout=subprocess.DEVNULL)
        iso_path.unlink()
        wim_path = temp_dir / 'install.wim'
        extract_from_wim(wim_path, name, dest)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def populate(branch, name, *, source=None, wim=None, iso_url=None, skip_existing=False):
    dest = config.delta_base_path(name, branch)
    if skip_existing and dest.is_file():
        print(f'Already cached: {dest}')
        return
    if source:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
    elif wim:
        extract_from_wim(Path(wim), name, dest)
    elif iso_url:
        extract_from_iso(iso_url, name, dest)
    else:
        raise ValueError('one of source/wim/iso_url is required')
    print(f'Cached baseline: {dest} ({dest.stat().st_size} bytes)')


def main():
    parser = argparse.ArgumentParser(description='Populate the delta-reconstruction base catalog.')
    parser.add_argument('--all', action='store_true', help='populate everything in config.delta_base_media')
    parser.add_argument('--branch', help='branch build number, e.g. 17763')
    parser.add_argument('--name', help='file name, e.g. ci.dll')
    parser.add_argument('--source', help='path to an already-extracted baseline file')
    parser.add_argument('--wim', help='path to an install.wim to extract the baseline from')
    parser.add_argument('--iso-url', help='URL of an install media ISO to extract the baseline from')
    args = parser.parse_args()

    if args.all:
        for branch, name, iso_url in config.delta_base_media:
            try:
                populate(branch, name, iso_url=iso_url, skip_existing=True)
            except Exception as e:
                print(f'WARNING: failed to populate {name} for branch {branch}: {e}')
        return

    if not args.branch or not args.name:
        parser.error('--branch and --name are required without --all')

    populate(int(args.branch), args.name, source=args.source, wim=args.wim, iso_url=args.iso_url)


if __name__ == '__main__':
    main()
