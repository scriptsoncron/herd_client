# HERD Python Client

import sys
import os
import json
import requests
import asyncio
import aiohttp
import time
import hashlib
import argparse
import re
import logging


def timing(f):
    def wrap(*args, **kwargs):
        time1 = time.time()
        ret = f(*args, **kwargs)
        time2 = time.time()
        logging.debug('{:s} function took {:.3f} s'.format(f.__name__, (time2 - time1)))
        return ret
    return wrap


def sha256sum(path):
    with open(path, "rb") as f:
        f_byte = f.read()
        result = hashlib.sha256(f_byte)
        return result.hexdigest()


class Herding:
    def __init__(self, **kwargs):
        self.conn = aiohttp.TCPConnector(limit_per_host=100, limit=0, ttl_dns_cache=300)
        self.token = kwargs.get('key')
        self.store = kwargs.get('output', False)
        self._type = kwargs.get('type')
        self.force = kwargs.get('force', False)
        self.action = kwargs.get('detonate')
        self.input = kwargs.get('input')

        self.headers = {"X-API-Key": self.token}
        self.shas = {"normal": [], "large": [], "all": []}
        self.results = {"normal": {"missing": [], "found": []}, "large": {"missing": [], "found": []}}
        self.search_errors = []
        self.upload_results = {}
        self.upload_failed = {}
        self.reports = {}

        self.gather_triage_list()
        self.search()
        if self.action:
            self.detonate()
        
        if self.store:
            json.dump(self.reports, open(f"{list(self.reports.keys())[0]}.json", 'w'))
            # self.report()

    @timing
    def gather_triage_list(self):
        # list of file paths in directories
        if os.path.isdir(self.input):
            if self.input.endswith('/'):
                self.input = self.input[:-1]
            for root, dirs, files in os.walk(self.input, topdown=False):
                for file in files:
                    if os.path.getsize(f"{root}/{file}") >= 6000000:
                        self.shas['large'].append((sha256sum(f"{root}/{file}"), f"{root}/{file}", file))
                    else:
                        self.shas['normal'].append((sha256sum(f"{root}/{file}"), f"{root}/{file}"))
        # path to file
        elif os.path.isfile(self.input):
            try:
                with open(self.input) as f:
                    shas = f.read().splitlines()
                    if len(shas[0]) == 64:
                        self.shas['normal'].extend([(x, None) for x in shas])
                    else:
                        self.shas['normal'].append((sha256sum(self.input), self.input))
            except:
                if os.path.getsize(self.input) >= 6000000:
                    self.shas['large'].append((sha256sum(self.input), self.input, self.input.split('/')[-1]))
                else:
                    self.shas['normal'].append((sha256sum(self.input), self.input))
        # string input
        else:
            # list of sha256
            if ',' in self.input:
                self.shas['normal'].extend([(x, None) for x in self.input.replace(' ', '').split(',')])
            elif self.input is None:
                with open('.last_upload', 'r') as f:
                    self.shas['normal'].extend([(x.split(',')[0], x.split(',')[1]) for x in f.read().splitlines()])
            # single sha256
            else:
                self.shas['normal'].append((self.input, None))

    @timing
    def search(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.hash_lookup())

        searched = len(self.shas['normal']) + len(self.shas['large'])
        found = len(self.results['normal']['found']) + len(self.results['large']['found'])
        print(f"\n[+] Searched {searched} SHA256 and {found} found\n")

    async def hash_lookup(self):
        session = aiohttp.ClientSession()

        async def get(sha, size):
            logging.info(f'hash lookup: {sha[0]} {self._type}')
            if self.store:
                action = 'report'
            else:
                action = 'status'
            async with session.get(f'https://api.herdsecurity.co/file?hash={sha[0]}&type={self._type}&action={action}',
                                   ssl=True, headers=self.headers) as response:
                try:
                    r = await response.read()
                    obj = json.loads(r)
                    logging.debug(f'lookup response: {obj}')
                    if 'error' in obj:
                        logging.warning(f"response error: {obj['error']}")
                    else:
                        if self.force:
                            self.results[size]['missing'].append(sha)
                        else:
                            if obj['status']['reported'] == 0:
                                self.results[size]['missing'].append(sha)
                            else:
                                self.results[size]['found'].append(sha[0])
                                if action == 'report':
                                    self.reports[sha[0]] = obj['dump']

                except json.decoder.JSONDecodeError:
                    res = re.search(r'<title>(.*?)<\/title>', r.decode('utf-8')).group(1)
                    logging.warning(f'hash lookup error: {res}')

        await asyncio.gather(*(get(sha, 'normal') for sha in self.shas['normal']))
        await asyncio.gather(*(get(sha, 'large') for sha in self.shas['large']))
        await session.close()
    
    @timing
    def detonate(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.file_upload())

        if self.upload_failed:
            logging.info(f"Upload fails :: {self.upload_failed}")

        uploaded = len(self.results['normal']['missing']) + len(self.results['large']['missing'])
        print(f"\n[+] Uploaded {uploaded} requests with {len(self.upload_results)} success\n")
        for x in self.upload_results:
            logging.info(f"uploaded {x} :: {self.upload_results[x]}")
    
    async def file_upload(self):
        session = aiohttp.ClientSession()

        if self.results['normal']['missing']:
            async def get(sha):
                logging.info(f'uploading: {sha[1]}')
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

            await asyncio.gather(*(get(sha) for sha in self.results['normal']['missing']))
        
        if self.results['large']['missing']:
            # pre-signed urls
            files = []
            for s in self.results['large']['missing']:
                files.append(s[2])
            
            data = {"key": files}
            r = requests.post('https://api.herdsecurity.co/signify', json=data, headers=self.headers)
            pre_urls = r.json()['urls']

            url_set = []
            for url in pre_urls:
                file_name = url['fields']['key']
                for s in self.results['large']['missing']:
                    if s[2] == file_name:
                        # sha, full path, url
                        url_set.append((s[0], s[1], url['url'], url['fields']))

            async def get_large(_set):
                logging.info(f'uploading: {_set[1]}')
                try:
                    _set[3]['file'] = open(_set[1], 'rb')
                    async with session.post(_set[2], ssl=True, data=_set[3]) as response:
                        try:
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


def main():
    parser = argparse.ArgumentParser(description='CLI tool to mass upload and search the HERD SANDBOX')
    parser.add_argument('-x', '--detonate',help="Detonate file(s); otherwise only search is performed", action='store_true')
    parser.add_argument('-i', '--input', required=True, help="path to directory/file, sha256, or list of sha256")
    list_of_reports = ["all", "static", "dynamic", "emulation"]
    parser.add_argument('-t', '--type', help='Output options: all, static, dynamic, emulation; Default: all', default="all", choices=list_of_reports)
    parser.add_argument('-o', '--output', action='store_true', help='Writes results into separate json files (<sha>.json)')
    parser.add_argument('-k', '--key', required=True, help="REQUIRED API Key")
    parser.add_argument('-f', '--force', action='store_true', help="Force re-upload")
    parser.add_argument('-d', '--debug', help="Print lots of debugging statements", action="store_const", dest="loglevel", const=logging.DEBUG,default=logging.WARNING)
    parser.add_argument('-v', '--verbose', help="Be verbose", action="store_const", dest="loglevel", const=logging.INFO)
    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel)

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)
    
    Herding(**vars(args))

if __name__ == "__main__":
    main()
