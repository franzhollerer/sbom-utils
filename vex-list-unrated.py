#!/usr/bin/python3
"""List unrated CVEs."""

import sys
import os.path
import argparse
import json
import textwrap


def is_file(parser, arg):
    if not os.path.exists(arg):
        parser.error(f'The file {arg} does not exist!')
    else:
        return arg


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='List unrated CVEs.'
        )
    parser.add_argument('--vex',
                        type=lambda x: is_file(parser, x),
                        required=True,
                        help= 'Vulnerability Exploitability eXchange (VEX) '
                              'file')
    return parser.parse_args()


def wrap_and_indent(s):
    s = textwrap.fill(s, width=76)
    s = textwrap.indent(s, ' ' * 4)
    return s


def list_unrated(vex):
    for vul in vex['vulnerabilities']:
        if not vul['affects'][0]['versions'][0]['status'].startswith('Please'):
            continue
        print(f"{vul['properties'][0]['value']}:")
        print(f"    Id: {vul['id']}")
        print()
        s = wrap_and_indent('Description: ' + vul['description'])
        print(s)
        print()


def main():
    args = parse_arguments()

    with open(args.vex) as f:
        vex = json.load(f)

    list_unrated(vex)


if __name__ == "__main__":
    main()

