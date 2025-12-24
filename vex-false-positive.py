#!/usr/bin/python3
"""Mark CVE as false positive in VEX file."""

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
        description='Mark CVE as false positive.'
        )
    parser.add_argument('--cve',
                        nargs='+',
                        required=True,
                        help='The affected CVE(s)')
    parser.add_argument('--vex-in',
                        type=lambda x: is_file(parser, x),
                        required=True,
                        help= 'Vulnerability Exploitability eXchange (VEX) '
                              'input file')
    parser.add_argument('--vex-out',
                        help= 'VEX output file (default: stdout)')
    parser.add_argument('--detail',
                        required=True,
                        help= 'Reason why considered as false positive')

    return parser.parse_args()


def false_positive(vex, cve, detail):
    for vul in vex['vulnerabilities']:
        id = vul['id']
        if not vul['id'] in cve:
            continue
        try:
            assert len(vul['affects']) == 1
        except AssertionError:
            print(f'{id} affects more than one component', file=sys.stderr)
            raise
        vul['affects'][0]['versions'][0]['status'] = 'unaffected'
        vul['analysis']['state'] = 'false_positive'
        del vul['analysis']['justification']
        del vul['analysis']['response']
        vul['analysis']['detail'] = detail


def main():
    args = parse_arguments()

    with open(args.vex_in) as f:
        vex = json.load(f)

    false_positive(vex, args.cve, args.detail)

    if args.vex_out:
        out = open(args.vex_out, 'w')
    else:
        out = open(sys.stdout.fileno(), 'w', closefd=False)
    with out:
        json.dump(vex, out, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()

