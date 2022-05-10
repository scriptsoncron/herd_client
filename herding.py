# HERD CLI tool
# running asyncio for asynchronous api requests
# https://blog.jonlu.ca/posts/async-python-http

import sys
import os
import json
import asyncio
import aiohttp
import time
import hashlib
from datetime import datetime
import argparse
import barn
import random
import secrets


def timing(f):
    def wrap(*args, **kwargs):
        time1 = time.time()
        ret = f(*args, **kwargs)
        time2 = time.time()
        print('\n{:s} function took {:.3f} s'.format(f.__name__, (time2 - time1)))

        return ret

    return wrap


def sha256sum(path):
    with open(path, "rb") as f:
        f_byte = f.read()
        result = hashlib.sha256(f_byte)
        return result.hexdigest()


class Herding:
    def __init__(self, **kwargs):
        # Initialize connection pool
        self.check_signed()
        self.conn = aiohttp.TCPConnector(limit_per_host=100, limit=0, ttl_dns_cache=300)
        self.PARALLEL_REQUESTS = 100
        self.token = None

        self._type = kwargs.get('type')
        if kwargs.get('detonate'):
            self.path = kwargs.get('detonate')
        else:
            self.path = kwargs.get('search')

        self.search_results = {"found": [], "missing": []}
        self.upload_results = {}
        self.upload_failed = {}
        self.reports = {}
        self.sha_list = []

    def check_signed(self):
        if '.herd' in os.listdir(os.path.expanduser('~')):
            with open(f"{os.path.expanduser('~')}/.herd", 'r') as f:
                self.token = f.read()
        else:
            with open(f"{os.path.expanduser('~')}/.herd", 'w') as f:
                self.token = secrets.token_urlsafe()
                f.write(self.token)

    async def file_upload(self):
        semaphore = asyncio.Semaphore(self.PARALLEL_REQUESTS)
        session = aiohttp.ClientSession(connector=self.conn)
        # session = aiohttp.ClientSession()

        if self.search_results['missing']:
            print('files to upload:\n\t', '\n\t'.join([x[1] for x in self.search_results['missing']]))
            print()

            async def get(sha):
                async with semaphore:

                    print(f'[+] uploading: {sha[1]}')
                    try:
                        async with session.post(f'https://api.herdsecurity.co/api-upload?token={self.token}', ssl=False,
                                                data={'file': open(sha[1], 'rb')}) as response:
                            try:
                                obj = json.loads(await response.read())
                                self.upload_results[sha[1]] = obj
                            except json.decoder.JSONDecodeError:
                                self.upload_failed[sha[1]] = response.read()
                    except:
                        self.upload_failed[sha[0]] = {'error': sys.exc_info()}

            await asyncio.gather(*(get(sha) for sha in self.search_results['missing']))
        await session.close()

    @timing
    def detonate(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.file_upload())
        # self.conn.close()

        if self.upload_failed:
            print(f"\nUpload fails\n\t{self.upload_failed}")

        print(f"\nUploaded {len(self.search_results['missing'])} requests with {len(self.upload_results)}")
        summary = ''.join(f"\t{x} :: {self.upload_results[x]}\n" for x in self.upload_results)
        print(summary)

    async def hash_lookup(self):
        # semaphore = asyncio.Semaphore(self.PARALLEL_REQUESTS)
        # session = aiohttp.ClientSession(connector=self.conn)
        session = aiohttp.ClientSession()

        async def get(sha):
            # async with semaphore:
            print(f'[+] hash lookup: {sha[0]}')
            async with session.get(f'https://api.herdsecurity.co/file?hash={sha[0]}&type={self._type}&token={self.token}', ssl=False) as response:
                obj = json.loads(await response.read())
                if 'error' not in obj:
                    self.search_results['found'].append(sha[0])
                    self.reports[sha[0]] = obj
                else:
                    self.search_results['missing'].append(sha)

        await asyncio.gather(*(get(sha) for sha in self.sha_list))
        await session.close()

    @timing
    def search(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.hash_lookup())
        # self.conn.close()

        print(f"\nSearched {len(self.sha_list)} SHA256 with {len(self.search_results['found'])} found")

        # summary = ''.join([f"\t{x} :: {list(self.search_results[x].keys())}\n" for x in self.search_results])
        # print(summary)

    def gather_triage_list(self):
        # list of file paths in directories
        if os.path.isdir(self.path):
            if self.path.endswith('/'):
                self.path = self.path[:-1]
            for root, dirs, files in os.walk(self.path, topdown=False):
                for file in files:
                    self.sha_list.append((sha256sum(f"{root}/{file}"), f"{root}/{file}"))
        # path to file
        elif os.path.isfile(self.path):
            if 'txt' in self.path:
                with open(self.path, 'r') as f:
                    self.sha_list.extend([(x, None) for x in f.read().splitlines()])
            else:
                self.sha_list.append((sha256sum(self.path), self.path))
        # sha string input
        else:
            # list of sha256
            if ',' in self.path:
                self.sha_list.extend([(x, None) for x in self.path.replace(' ', '').split(',')])
            # single sha256
            else:
                self.sha_list.append((self.path, None))

    def write(self):
        for sha in self.reports:
            with open(f'{sha}.json', 'w') as f:
                json.dump(self.reports[sha], f)

@timing
def main():
    print('''
        
    ██╗  ██╗███████╗██████╗ ██████╗      ██████╗██╗     ██╗    ████████╗ ██████╗  ██████╗ ██╗     
    ██║  ██║██╔════╝██╔══██╗██╔══██╗    ██╔════╝██║     ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
    ███████║█████╗  ██████╔╝██║  ██║    ██║     ██║     ██║       ██║   ██║   ██║██║   ██║██║     
    ██╔══██║██╔══╝  ██╔══██╗██║  ██║    ██║     ██║     ██║       ██║   ██║   ██║██║   ██║██║     
    ██║  ██║███████╗██║  ██║██████╔╝    ╚██████╗███████╗██║       ██║   ╚██████╔╝╚██████╔╝███████╗
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝      ╚═════╝╚══════╝╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
                                                                                                  
    ''')
    print(random.choice([barn.cow_1, barn.cow_2, barn.cow_3])())

    parser = argparse.ArgumentParser(description='CLI tool to mass upload and search the HERD SANDBOX')
    parser.add_argument('-x', '--detonate', metavar='FILE/DIRECTORY')
    parser.add_argument('-s', '--search', metavar='<SHA256>/FILE',
                        help="single sha, list of shas, or file of shas newline delimited")
    parser.add_argument('-t', '--type', metavar='ALL/STATIC/DYNAMIC/EMULATION', default='all')
    parser.add_argument('-o', '--output', action='store_true', help='outputs json response to file -> <sha>.json')
    args = parser.parse_args()
    print(vars(args))

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    run = Herding(**vars(args))
    run.gather_triage_list()
    if vars(args)['detonate']:
        run.search()
        run.detonate()
        if run.sha_list:
            d = datetime.today().strftime('%Y-%m-%d_%H:%M:%S')
            with open(f'upload_{d}.txt', 'w') as f:
                for x in run.sha_list:
                    f.write(x[0] + '\n')
            if vars(args)['output']:
                run.write()
    elif vars(args)['search']:
        run.search()
        if run.reports:
            if vars(args)['output']:
                run.write()
    else:
        sys.exit()


if __name__ == "__main__":
    main()
