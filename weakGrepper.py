#!/usr/bin/env python3
import os
import re
from termcolor import colored
import constants
import sys


def searchAll(regs, data):
    matches = []
    for r in regs:
        if type(r) is str:
            r = r.encode()
            mo = re.findall(r, data, re.IGNORECASE)
        else:
            # it was case-sensitive
            mo = re.findall(r, data)
        if len(mo) > 0:
            for m in mo:
                m = m.decode()
                if m not in matches:
                    matches.append(m)
    if len(matches) > 0:
        return matches


def searchWeak(key, dir):
    print(colored('Searching for {}...'.format(key), 'green'))

    for (dirpath, dirnames, filenames) in os.walk(dir, followlinks=True):
        for names in filenames:
            path = '{}/{}'.format(dirpath, names)
            if os.path.isfile(path):
                try:
                    with open(path, 'rb') as f:
                        data = f.read()
                        # break when one family has matched for this file
                        for patterFamily in constants.PATTERNS[key]:
                            res = searchAll(patterFamily[1], data)
                            if res is not None:
                                for m in res:
                                    m = "\t{} : Found pattern '{}'".format(path, m)
                                    sev = patterFamily[0]
                                    if sev == constants.severity.INFO:
                                        print(colored(m, 'green'))
                                    elif sev == constants.severity.WARNING:
                                        print(colored(m, 'yellow'))
                                    elif sev == constants.severity.CRITIC:
                                        print(colored(m, 'red'))
                                    else:
                                        print(m)
                                break
                except PermissionError:
                    print("Skipping, {} : Permission denied".format(path))


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print('Usage : {} <dir>'.format(sys.argv[0]))
        sys.exit(0)

    dir = sys.argv[1]

    if not os.path.isdir(dir):
        print(colored("The directory specified doesn't exist", 'red'))
        sys.exit(0)

    for key in constants.PATTERNS:
        searchWeak(key, dir)
