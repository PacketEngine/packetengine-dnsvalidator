import sys
import signal
import logging
import urllib3
import argparse
import os

import pathlib as pl

from typing import List, Optional
import re
import string
import random
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, wait


##->> Configure version info
__version__ = '3.0.0'

##->> Configure output colours
class colors_cls:
    def __init__(self):
        self.grey="\x1b[0;37m"
        self.green="\x1b[0;32m"
        self.blue="\x1b[0;34m"
        self.cyan="\x1b[0;36m"
        self.purple="\x1b[0;35m"
        self.yellow="\x1b[0;33m"
        self.red="\x1b[0;31m"
        self.bold_red="\x1b[1;31m"
        self.reset="\x1b[0m"
colors = colors_cls()

##->> IPv4 regex
regex = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.]){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

##->> Baseline server whsoe answer we trust
baselinesrvs = [
    '1.1.1.1', #-> OpenDNS
    '8.8.8.8', #-> Google
    '8.8.4.4', #-> Google
    '9.9.9.9', #-> Quad9
]


##->> Baseline domains to validate against
baselinechecks = [
    'starbucks.com.sg',
    'mayoclinic.org',
]

##->> Domains to check form DNS Poisoning
nxdomainchecks = [
    'facebook.com',
    'google.com',
    'microsoft.com'
]

##->> Configure logger
def create_custom_logger(name: 'str') -> 'logging.Logger':
    """ Creates a custom formatted logger named <name> """

    # Create logger with "someName"
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    return logger

def add_custom_file_handler(logger: 'logging.Logger', logFile: 'str') -> 'logging.Logger':
    fh = logging.FileHandler(logFile, mode='w', encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(CustomFormatter())
    logger.addHandler(fh)
    return logger

class CustomFormatter(logging.Formatter):
    """ Logging Formatter that adds colors and, count warning & errors. """

    log_HeadFormat = '%(asctime)s ⋞ {levelEmoji} ⋟ '

    FORMATS = {
        logging.DEBUG: log_HeadFormat.format(levelEmoji='\U0001F4A8') + '%(message)s' + colors.reset,
        logging.INFO: log_HeadFormat.format(levelEmoji='\U0001F4AC') + '%(msgC)s%(message)s' + colors.reset,
        logging.WARNING: log_HeadFormat.format(levelEmoji='\U0001F4A3') + colors.yellow + '%(message)s' + colors.reset,
        logging.ERROR: log_HeadFormat.format(levelEmoji='\U0001F4A2') + colors.red + '%(message)s' + colors.reset,
        logging.CRITICAL: log_HeadFormat.format(levelEmoji='\U0001F4A5') + colors.bold_red + '%(message)s (%(filename)s:%(lineno)d)' + colors.reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        # formatter = logging.Formatter(log_fmt, datefmt='%I:%M:%S %p')
        formatter = logging.Formatter(log_fmt, datefmt='%H:%M:%S')
        return formatter.format(record)

logger = create_custom_logger('DNSValidator')
logger.propagate = False

def get_args(argList: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--verbose", help="Print additional error messages (default: false)",
        action="store_true")

    parser.add_argument("-i", "--input-file", help="Input file containing DNS server addresses (one per line) (default: public-dns.info/nameservers.txt)",
        action="store", type=str, required=False)
    parser.add_argument("-o", "--output-file", help="Output file name (default: ./resolvers.txt)",
        action="store", type=str, required=False, default='resolvers.txt')
    parser.add_argument("-r", "--root-domain", help="Root domain to compare (non-geolocated) (default: starbucks.com.sg)",
        action="store", type=str, required=False, default='starbucks.com.sg')
    parser.add_argument("-t", "--threads", help="Concurrent threads to run (default: 2)",
        action="store", type=int, required=False, default=2)

    parser.add_argument('-V', '--version', action='version', version=__version__)

    return parser.parse_args(argList)

# Generate a random string of specified length
def get_rand_str(lng: int) -> str:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(lng))

# Get baseline DNS servers
def get_baselines(rootDom: str, servers: Optional[List[str]] = baselinesrvs, checks: Optional[List[str]] = baselinechecks) -> tuple:
    logger.info('Checking baseline servers...', extra={'msgC': ''})
    baselines = {}

    for server in servers:
        baselines[server] = []
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server]
        resolver.timeout = 1
        resolver.lifetime = 3

        for target in checks:
            d = {}

            try:
                rans = resolver.resolve(target, 'A')
                d['ipaddr'] = str(rans[0])
            except dns.exception.Timeout:
                logger.error(f'Baseline server timeout {server}')
                continue
            except Exception as e:
                logger.error(f'Error resolving {target} on {server}: {e}')
                continue

            try:
                resolver.resolve(f'{get_rand_str(10)}.{target}', 'A')
                d['nxdomain'] = False
            except dns.resolver.NXDOMAIN:
                d['nxdomain'] = True
            except dns.exception.Timeout:
                logger.error(f'Baseline server timeout {server}')
                continue
            except Exception as e:
                logger.error(f'Error resolving NXDOMAIN for {target} on {server}: {e}')
                continue

            baselines[server].append({target: d})

    # Safely iterate over all entries to extract the baseline for rootDom
    ipset = {
        entry[rootDom]['ipaddr']
        for server in baselines if baselines[server]
        for entry in baselines[server]
        if rootDom in entry and 'ipaddr' in entry[rootDom]
    }
    nxset = {
        entry[rootDom]['nxdomain']
        for server in baselines if baselines[server]
        for entry in baselines[server]
        if rootDom in entry and 'nxdomain' in entry[rootDom]
    }

    try:
        assert len(ipset) == 1 and len(nxset) == 1 and list(nxset)[0] is True
        return baselines, list(ipset)[0]
    except AssertionError:
        logger.critical(f'Baseline validation failed. IP Set: {ipset}, NX Set: {nxset}')
        sys.exit(1)

# Validate individual DNS server
def check_server(server: str, rootDom: str) -> Optional[str]:
    srvstr = f'{colors.cyan}{server}{colors.reset}'
    logger.info(f'Checking server {srvstr}', extra={'msgC': ''})

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]

    nxstr = get_rand_str(10)

    # Validate NXDOMAIN checks
    for nxdomain in nxdomainchecks:
        try:
            resolver.resolve(f'{nxstr}.{nxdomain}', 'A')
            logger.warning(f'DNS poisoning detected, skipping server {srvstr}')
            return None
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            logger.error(f'Error checking DNS poisoning on server {srvstr}: {e}')
            return None

    # Validate root-domain NXDOMAIN
    try:
        resolver.resolve(f'{nxstr}.{rootDom}', 'A')
    except dns.resolver.NXDOMAIN:
        pass
    except dns.exception.Timeout:
        logger.error(f'IP Address validation timeout on server {srvstr}')
        return None
    except Exception as e:
        logger.error(f'Error validating server {srvstr}: {e}')
        return None

    # Validate root-domain IP
    try:
        rans = resolver.resolve(rootDom, 'A')
        if str(rans[0]) == goodip:
            logger.info(f'Successfully validated server {srvstr}', extra={'msgC': colors.green})
            return server
        else:
            logger.error(f'Invalid response, skipping server {srvstr}')
            return None
    except dns.exception.Timeout:
        logger.error(f'IP Address validation timeout on server {srvstr}')
        return None
    except Exception as e:
        logger.error(f'Error validating server {srvstr}: {e}')
        return None

# Main function to run validation
def run(servers: List[str], workers: int, rootDom: str, fileName: str, vocal: bool = False) -> None:
    global verbose, goodip
    verbose = vocal

    _, goodip = get_baselines(rootDom)

    futures = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for server in servers:
            futures.append(executor.submit(check_server, server, rootDom))

    done, _ = wait(futures)

    validServers = [future.result() for future in done if future.result()]

    if validServers:
        with pl.Path(fileName).open('w') as fout:
            fout.writelines(f'{server}\n' for server in validServers)

def main():
    argvals = None
    argvals = sys.argv[1:]
    args = get_args(argvals)

    ##->> Fetch Public DNS Servers if INPUT is not provided
    if args.input_file:
        if pl.Path(args.input_file).exists():
            logger.info(f'Reading nameserver list from file...', extra={'msgC':colors.cyan})
            servers = pl.Path(args.input_file).read_text().splitlines()
            servers = list(filter(lambda x: regex.match(x), servers))
        else:
            logger.error(f'Failed to read nameserver list from file')
            if args.verbose: logger.debug(f'File not found: {args.input_file}')

    else:
        logger.info('No input provided, fetching nameservers from https://public-dns.info', extra={'msgC':colors.cyan})
        http = urllib3.PoolManager()
        r = http.request('Get', 'https://public-dns.info/nameservers.txt')
        servers = r.data.decode().splitlines()
        servers = list(filter(lambda x: regex.match(x), servers))

    ##->> Declare signal handler to immediately exit on KeyboardInterrupt
    def signal_handler(signal, frame):
        os._exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    ##->> Run the script
    run(
        servers=servers,
        workers=args.threads,
        rootDom=args.root_domain,
        fileName=args.output_file,
        vocal=args.verbose
    )

    ##->> We're done, mate!
    sys.exit(0)

if __name__ == '__main__':
    main()
