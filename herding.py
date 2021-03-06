# HERD Python Client

import sys
import os
import json
import requests
import asyncio
import aiohttp
import time
import hashlib
from datetime import datetime
import argparse
import barn
import random
import secrets
import re


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
        self.token = kwargs.get('key')
        self.headers = {"X-API-Key": self.token}

        self._type = kwargs.get('type')
        if kwargs.get('detonate'):
            self.path = kwargs.get('detonate')
        else:
            self.path = kwargs.get('search')

        if kwargs.get('force'):
            self.force = 'true'
        else:
            self.force = 'false'
        self.search_results = {"found": [], "missing": [], "missing_large": []}
        self.upload_results = {}
        self.upload_failed = {}
        self.reports = {}
        self.sha_list = []
        self.large_sha_list = []

    def check_signed(self):
        if '.herd' in os.listdir(os.path.expanduser('~')):
            with open(f"{os.path.expanduser('~')}/.herd", 'r') as f:
                self.token = f.read()
        else:
            with open(f"{os.path.expanduser('~')}/.herd", 'w') as f:
                self.token = secrets.token_urlsafe()
                f.write(self.token)

    async def file_upload(self):
        # semaphore = asyncio.Semaphore(self.PARALLEL_REQUESTS)
        session = aiohttp.ClientSession()

        if self.search_results['missing']:
            print('files to upload:\n\t', '\n\t'.join([x[1] for x in self.search_results['missing']]))
            print()

            async def get(sha):
                print(f'[+] uploading: {sha[1]}')
                try:
                    async with session.post(f'https://api.herdsecurity.co/detonate?force={self.force}', ssl=True,
                                            data={'file': open(sha[1], 'rb')}, headers=self.headers) as response:
                        try:
                            obj = json.loads(await response.read())
                            self.upload_results[sha[1]] = obj
                        except json.decoder.JSONDecodeError:
                            self.upload_failed[sha[1]] = response.read()
                except:
                    self.upload_failed[sha[0]] = {'error': sys.exc_info()}

            await asyncio.gather(*(get(sha) for sha in self.search_results['missing']))
        
        if self.search_results['missing_large']:
            print('files to upload:\n\t', '\n\t'.join([x[1] for x in self.search_results['missing_large']]))
            print()

            # pre-signed urls
            files = []
            for s in self.search_results['missing_large']:
                files.append(s[2])
            
            data = {"key": files}
            r = requests.post('https://api.herdsecurity.co/signify', json=data, headers=self.headers)
            pre_urls = r.json()['urls']

            url_set = []
            for url in pre_urls:
                file_name = url['fields']['key']
                for s in self.search_results['missing_large']:
                    if s[2] == file_name:
                        # sha, full path, url
                        url_set.append((s[0], s[1], url['url'], url['fields']))

            async def get_large(_set):
                print(f'[+] uploading: {_set[1]}')
                try:
                    _set[3]['file'] = open(_set[1], 'rb')
                    async with session.post(_set[2], ssl=True, data=_set[3]) as response:
                        try:
                            # obj = json.loads(await response.read())
                            obj = await response
                            if response.status == 204:
                                self.upload_results[_set[0]] = obj
                            else:
                                self.upload_failed[_set[1]] = [response.status, response]
                        except:
                            self.upload_failed[_set[1]] = {'error': sys.exc_info()}
                except:
                    self.upload_failed[_set[1]] = {'error': sys.exc_info()}

            await asyncio.gather(*(get_large(_set) for _set in url_set))
        await session.close()

    # @timing
    def detonate(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.file_upload())

        if self.upload_failed:
            print(f"\nUpload fails\n\t{self.upload_failed}")

        print(f"\nUploaded {len(self.search_results['missing'])} requests with {len(self.upload_results)}")
        summary = ''.join(f"\t{x} :: {self.upload_results[x]}\n" for x in self.upload_results)
        print(summary)

    async def hash_lookup(self):
        session = aiohttp.ClientSession()

        async def get(sha):
            print(f'[+] hash lookup: {sha[0]} {self._type}')
            async with session.get(f'https://api.herdsecurity.co/file?hash={sha[0]}&type={self._type}',
                                   ssl=True, headers=self.headers) as response:
                try:
                    r = await response.read()
                    obj = json.loads(r)
                    if 'error' not in obj:
                        if 'message' in obj:
                            self.reports[sha[0]] = obj
                        else:
                            if self.force == 'true':
                                self.search_results['missing'].append(sha)
                            else:
                                self.search_results['found'].append(sha[0])
                                self.reports[sha[0]] = obj
                    else:
                        self.search_results['missing'].append(sha)
                except json.decoder.JSONDecodeError:
                    res = re.search(r'<title>(.*?)<\/title>', r.decode('utf-8')).group(1)
                    print('Error: ', res)

        await asyncio.gather(*(get(sha) for sha in self.sha_list))
        # await session.close()

        async def get_large(sha):
            print(f'[+] hash lookup: {sha[0]}')
            async with session.get(f'https://api.herdsecurity.co/file?hash={sha[0]}&type={self._type}',
                                   ssl=True, headers=self.headers) as response:
                try:
                    r = await response.read()
                    obj = json.loads(r)
                    if 'error' not in obj:
                        if 'message' in obj:
                            self.reports[sha[0]] = obj
                        else:
                            if self.force == 'true':
                                self.search_results['missing_large'].append(sha)
                            else:
                                self.search_results['found'].append(sha[0])
                                self.reports[sha[0]] = obj
                    else:
                        self.search_results['missing_large'].append(sha)
                except json.decoder.JSONDecodeError:
                    res = re.search(r'<title>(.*?)<\/title>', r.decode('utf-8')).group(1)
                    print('Error: ', res)

        await asyncio.gather(*(get_large(sha) for sha in self.large_sha_list))
        await session.close()

    # @timing
    def search(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.hash_lookup())

        print(f"\n[+] Searched {len(self.sha_list)} SHA256 and {len(self.search_results['found'])} found\n")

    def gather_triage_list(self):
        # list of file paths in directories
        if os.path.isdir(self.path):
            if self.path.endswith('/'):
                self.path = self.path[:-1]
            for root, dirs, files in os.walk(self.path, topdown=False):
                for file in files:
                    if os.path.getsize(f"{root}/{file}") >= 6000000:
                        self.large_sha_list.append((sha256sum(f"{root}/{file}"), f"{root}/{file}", file))
                    else:
                        self.sha_list.append((sha256sum(f"{root}/{file}"), f"{root}/{file}"))
        # path to file
        elif os.path.isfile(self.path):
            try:
                with open(self.path) as f:
                    shas = f.read().splitlines()
                    if len(shas[0]) == 64:
                        self.sha_list.extend([(x, None) for x in shas])
                    else:
                        self.sha_list.append((sha256sum(self.path), self.path))
            except:
                if os.path.getsize(self.path) >= 6000000:
                    self.large_sha_list.append((sha256sum(self.path), self.path, self.path.split('/')[-1]))
                else:
                    self.sha_list.append((sha256sum(self.path), self.path))
        # string input
        else:
            # list of sha256
            if ',' in self.path:
                self.sha_list.extend([(x, None) for x in self.path.replace(' ', '').split(',')])
            elif self.path is None:
                with open('.last_upload', 'r') as f:
                    self.sha_list.extend([(x.split(',')[0], x.split(',')[1]) for x in f.read().splitlines()])
            # single sha256
            else:
                self.sha_list.append((self.path, None))

    def write(self):
        for sha in self.reports:
            if 'message' in self.reports[sha]:
                if self.reports[sha]['message'] == 'Forbidden':
                    print('[-] Wrong API Key\n')
            else:
                with open(f'{sha}.json', 'w') as f:
                    json.dump(self.reports[sha], f)
                print(f'Writing -> {sha}.json\n')

# @timing
def main():
    print('''
        
    ?????????  ?????????????????????????????????????????????????????? ?????????????????????      ??????????????????????????????     ?????????    ??????????????????????????? ?????????????????????  ????????????????????? ?????????     
    ?????????  ?????????????????????????????????????????????????????????????????????????????????    ?????????????????????????????????     ?????????    ??????????????????????????????????????????????????????????????????????????????????????????     
    ??????????????????????????????????????????  ?????????????????????????????????  ?????????    ?????????     ?????????     ?????????       ?????????   ?????????   ??????????????????   ??????????????????     
    ??????????????????????????????????????????  ?????????????????????????????????  ?????????    ?????????     ?????????     ?????????       ?????????   ?????????   ??????????????????   ??????????????????     
    ?????????  ??????????????????????????????????????????  ?????????????????????????????????    ?????????????????????????????????????????????????????????       ?????????   ??????????????????????????????????????????????????????????????????????????????
    ?????????  ??????????????????????????????????????????  ??????????????????????????????      ??????????????????????????????????????????????????????       ?????????    ?????????????????????  ????????????????????? ????????????????????????
                                                                                                  
    ''')
    print(random.choice([barn.cow_1, barn.cow_2, barn.cow_3])())

    parser = argparse.ArgumentParser(description='CLI tool to mass upload and search the HERD SANDBOX')
    parser.add_argument('-x', '--detonate', metavar='', help="Input: file, directory")
    parser.add_argument('-s', '--search', metavar='', help="Search by a single SHA, list of SHAs, file of SHAs newline delimited, or by 'last' for last uploaded files")
    list_of_choices = ["all", "static", "dynamic", "emulation"]
    parser.add_argument('-t', '--type', metavar='', help='Output options: all, static, dynamic, emulation; Default: all', default="all", choices=list_of_choices)
    parser.add_argument('-o', '--output', action='store_true', help='Writes results into separate json files (<sha>.json)')
    parser.add_argument('-k', '--key', metavar='', required=True, help="REQUIRED API Key")
    parser.add_argument('-f', '--force', action='store_true', help="Force re-upload")
    args = parser.parse_args()
    # print(vars(args))

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
            with open(f'.last_upload', 'w') as f:
                for x in run.sha_list:
                    f.write(f"{x[0]},{x[1]}" + '\n')
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
