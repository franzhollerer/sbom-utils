#!/usr/bin/python3
"""Merge rated CVEs from an older into a newer VEX file."""

import sys
import os.path
import argparse
import json


def is_file(parser, arg):
    if not os.path.exists(arg):
        parser.error(f'The file {arg} does not exist!')
    else:
        return arg


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Merge rated CVEs from an older into a newer VEX file.'
        )
    parser.add_argument('--vex-from',
                        type=lambda x: is_file(parser, x),
                        required=True,
                        help= 'Vulnerability Exploitability eXchange (VEX) '
                              'file to merge from')
    parser.add_argument('--vex-into',
                        type=lambda x: is_file(parser, x),
                        required=True,
                        help= 'VEX file to merge into')

    return parser.parse_args()


def merge(vex_from, vex_into):
    # Search for rated CVEs in 'vex-from' data.
    rated = {}
    for vul in vex_from['vulnerabilities']:
        id = vul['id']
        try:
            assert len(vul['affects']) == 1
        except AssertionError:
            print(f'{id} affects more than one component', file=sys.stderr)
            raise
        if vul['affects'][0]['versions'][0]['status'].startswith('Please'):
            continue
        rated[id] = vul

    # Merge rated CVEs into 'vex-into' data.
    for vul in vex_into['vulnerabilities']:
        id = vul['id']
        try:
            assert len(vul['affects']) == 1
        except AssertionError:
            print(f'{id} affects more than one component', file=sys.stderr)
            raise
        if not vul['affects'][0]['versions'][0]['status'].startswith('Please'):
            continue
        if id in rated:
            vul['affects'][0]['versions'][0]['status'] = \
                rated[id]['affects'][0]['versions'][0]['status']
            vul['analysis'] = rated[id]['analysis']


def main():
    args = parse_arguments()

    with open(args.vex_from) as f:
        vex_from = json.load(f)
    with open(args.vex_into) as f:
        vex_into = json.load(f)

    merge(vex_from, vex_into)

    with open(args.vex_into, 'w') as f:
        json.dump(vex_into, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()

