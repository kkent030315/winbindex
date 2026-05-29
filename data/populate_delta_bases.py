import argparse
import subprocess
import tempfile
import shutil
from pathlib import Path

import config


# Populate the delta-reconstruction base catalog.
#
# Files shipped only as forward differentials are reconstructed in
# upd03_parse_manifests by applying the forward delta to the branch's baseline
# (RTM) file. The baseline bytes can't be fetched from the symbol server
# (timestamp+SizeOfImage collisions), so they're sourced once per (file, branch)
# from install media and cached here at:
#
#   data/delta_bases/<branch>/<name>   (a local runtime cache, gitignored,
#   deliberately outside out_path so it is never committed)
#
# <branch> is the third version component (e.g. 17763 for 1809, 22621 for 22H2),
# matching the manifest assemblyIdentity version. The cached file is the RTM
# build (e.g. 10.0.17763.1) of that branch.
#
# Examples:
#   # from an already-extracted file
#   python populate_delta_bases.py --branch 17763 --name ci.dll --source C:\rtm\ci.dll
#
#   # straight from install media (extracts <name> from the wim's first image)
#   python populate_delta_bases.py --branch 17763 --name ci.dll --wim D:\sources\install.wim


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


def main():
    parser = argparse.ArgumentParser(description='Populate the delta-reconstruction base catalog.')
    parser.add_argument('--branch', required=True, help='branch build number, e.g. 17763')
    parser.add_argument('--name', required=True, help='file name, e.g. ci.dll')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--source', help='path to an already-extracted baseline file')
    group.add_argument('--wim', help='path to an install.wim/ISO to extract the baseline from')
    args = parser.parse_args()

    dest = config.delta_base_path(args.name, args.branch)

    if args.source:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.source, dest)
    else:
        extract_from_wim(Path(args.wim), args.name, dest)

    print(f'Cached baseline: {dest} ({dest.stat().st_size} bytes)')


if __name__ == '__main__':
    main()
