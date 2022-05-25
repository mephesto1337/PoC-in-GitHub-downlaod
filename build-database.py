#! /usr/bin/env python3

from typing import Any, Dict, Iterable

import argparse
import datetime
import dataclasses
import json
import logging
import re
import os
import subprocess
import sys

import requests
from progress.bar import ChargingBar

POC_IN_GITHUB = 'https://github.com/nomi-sec/PoC-in-GitHub'

logging.basicConfig(
    stream=sys.stderr,
    format='[%(asctime)s] %(name)s - %(levelname)s - %(message)s',
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper())
)
logger = logging.getLogger(os.path.splitext(os.path.basename(__file__))[0])


class EmptyRepository(Exception):
    pass


@dataclasses.dataclass
class CVE:
    year: int
    id: int

    def __str__(self) -> str:
        return f'CVE-{self.year}-{self.id:04}'

    @classmethod
    def fromstr(cls, string: str) -> Any:
        reg = re.compile(r'^CVE-(?P<year>\d+)-(?P<id>\d+)')
        m = reg.search(string)
        if not m:
            raise ValueError(f'Bad format for CVE: {string!r}')
        return cls(**m.groupdict())


@dataclasses.dataclass
class Exploit:
    cve: CVE
    data: Dict[str, Any]

    def __str__(self) -> str:
        return f'{self.cve}: {self.data["full_name"]}'

    def owner(self) -> Dict[str, str]:
        return self.data['owner']

    def login(self) -> str:
        return self.owner()['login']

    def url(self) -> str:
        return self.data['html_url']

    def get_branch_name(self) -> str:
        """
        Returns branch name for git
        """
        cached_branchname = os.path.join(os.path.dirname(self.output_file()), f'.{self.login()}.branch')
        try:
            with open(cached_branchname, 'rt') as f:
                return f.readline().strip()
        except FileNotFoundError:
            branch = self.get_branch_name_from_github()
            with open(cached_branchname, 'wt') as f:
                f.write(f'{branch}\n')
            return branch

    def get_branch_name_from_github(self) -> str:
        """
        Returns branch name fro, github
        """
        r = requests.get(self.url())
        m = re.search(r'\bhref="/{login}/{name}/commits/(?P<branch>[^/"]+)"'.format(
            login=re.escape(self.login()), name=self.data['name']
        ), r.text)
        if not m:
            if 'This repository is empty.' in r.text:
                raise EmptyRepository(self.url())
            raise RuntimeError(f'Cannot get branch name from github for {self.url()}')
        return m.group('branch')

    def output_file(self) -> str:
        """
        Get outfile
        """
        return os.path.join(str(self.cve.year), str(self.cve), self.login() + '.zip')

    def updated_at(self) -> int:
        """
        Returns last update time as a UNIX timestamp
        """
        return int(datetime.datetime.strptime(self.data['updated_at'], '%Y-%m-%dT%H:%M:%SZ').strftime('%s'))

    def refresh_zip(self):
        """
        Downloads repository's zip if necessary
        """
        should_download = False
        output_file = self.output_file()
        os.makedirs(os.path.dirname(output_file), mode=0o755, exist_ok=True)
        try:
            st = os.stat(output_file)
            if st.st_mtime < self.updated_at():
                should_download = True
        except FileNotFoundError:
            should_download = True

        if should_download:
            self.download_zip(output_file)

    def download_zip(self, output_file: str):
        """
        Downloads repository's zip if necessary
        """
        try:
            branch = self.get_branch_name()
            r = requests.get(f'{self.url()}/archive/refs/heads/{branch}.zip', stream=True)
            with open(output_file, 'wb') as f:
                for chunk in r.iter_content(8192):
                    f.write(chunk)
        except EmptyRepository:
            with open(output_file, 'wb') as f:
                f.write(b'Empty repository')
        os.utime(output_file, (self.updated_at(), self.updated_at()))


def setup_pocs_metadata():
    """
    Downloads & updated https://github.com/nomi-sec/PoC-in-GitHub
    """
    try:
        repository = os.path.basename(POC_IN_GITHUB)
        subprocess.check_call(['git', 'pull'], cwd=repository)
    except FileNotFoundError:
        subprocess.check_call(['git', 'clone', POC_IN_GITHUB])


def collect_jsons(root_dir: str) -> Iterable[str]:
    """
    Finds all json files in `root_dir`
    """
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Ignore '.*' directories
        dot_dirs = [d for d in dirnames if d.startswith('.')]
        for dot_dir in dot_dirs:
            dirnames.remove(dot_dir)
        for filename in filenames:
            if filename.endswith('.json'):
                yield os.path.join(dirpath, filename)


def main():
    def parse_args():
        parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument(
            '--pocs-dir', dest='pocs_dir', default='pocs', type=str,
            help='Output directory for pocs'
        )
        args = parser.parse_args()
        return args

    args = parse_args()
    logger.debug('args = %r', args)
    try:
        os.chdir(os.path.dirname(__file__))
        logger.debug('CWD = %s', os.getcwd())
        setup_pocs_metadata()
        pocs = []
        for filename in collect_jsons('.'):
            cve = CVE.fromstr(os.path.basename(filename))
            with open(filename, 'rt') as f:
                data = json.load(f)
            for poc in data:
                pocs.append(Exploit(cve, poc))

        os.chdir(args.pocs_dir)
        logger.info('Got %d pocs', len(pocs))
        for poc in ChargingBar('Pocs', suffix='%(percent)d%% (%(iter_value)s)').iter(pocs):
            try:
                poc.refresh_zip()
            except EmptyRepository:
                logger.debug('Repository is empty: %s', poc.url())
            except Exception as e:
                logger.error('Cannot fetch %s: %s', poc, str(e), exc_info=True)
    except Exception as e:
        te = type(e)
        show_bt = logger.getEffectiveLevel() <= logging.DEBUG
        logger.error(
            'Caught exception %s.%s: %s',
            te.__module__, te.__name__, str(e), exc_info=show_bt
        )
        return 1
    else:
        return 0


if __name__ == '__main__':
    sys.exit(main())
