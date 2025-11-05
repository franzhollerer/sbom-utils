#!/usr/bin/python3
"""Annotates CVE status in VEX file with information from Yocto build."""

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
        description='Annotates CVE status with information from Yocto build.'
        )
    parser.add_argument('--cve',
                        nargs='+',
                        type=lambda x: is_file(parser, x),
                        required=True,
                        help='Yocto CVE json file(s)')
    parser.add_argument('--vex-in',
                        type=lambda x: is_file(parser, x),
                        required=True,
                        help= 'Vulnerability Exploitability eXchange (VEX) '
                              'input file')
    parser.add_argument('--vex-out',
                        help= 'VEX output file (default: stdout)')

    return parser.parse_args()


def get_treated_cves(files):
    cves = {}
    for fn in files:
        with open(fn) as f:
            d = json.load(f)
        package = d['package']
        try:
            assert len(package) == 1
        except AssertionError:
            print(f'AssertionError occurred while processing {fn}',
                  file=sys.stderr)
            raise

        for issue in package[0]['issue']:
            cve = {}
            if issue['status'] == 'Unpatched':
                continue
            cve['status'] = issue['status']
            if 'description' in issue:
                cve['description'] = issue['description']
            cves[issue['id']] = cve
    return cves


def annotate_vex(treated, vex):
    for vul in vex['vulnerabilities']:
        print(vul['id'])


def main():
    args = parse_arguments()

    with open(args.vex_in) as f:
        vex = json.load(f)

    treated = get_treated_cves(args.cve)
    annotate_vex(treated, vex)

    print('-----------------------> remove sys.exit(0)')
    sys.exit(0)

    if args.vex_out:
        out = open(args.vex_out, 'w')
    else:
        out = open(sys.stdout.fileno(), 'w', closefd=False)
    with out:
        json.dump(vex, out, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()

