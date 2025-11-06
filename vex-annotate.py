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
            else:
                cve['description'] = None

            cves[issue['id']] = cve
    return cves


def annotate_vex(treated, vex):
    for vul in vex['vulnerabilities']:
        id = vul['id']
        try:
            assert len(vul['affects']) == 1
        except AssertionError:
            print(f'{id} affects more than one component', file=sys.stderr)
            raise
        if not id in treated:
            continue
        status = treated[id]['status']
        description = treated[id]['description']
        match status:
            case 'Patched':
                vul['affects'][0]['versions'][0]['status'] = 'affected'
                vul['analysis']['state'] = 'resolved'
                del vul['analysis']['justification']
                vul['analysis']['response'] = ['workaround_available']
                vul['analysis']['detail'] = ['Patched through Yocto']
            case 'Ignored':
                vul['affects'][0]['versions'][0]['status'] = 'affected'
                vul['analysis']['state'] = 'not_affected'
                vul['analysis']['justification'] = 'requires_dependency'
                del vul['analysis']['response']
                s = 'Ignored through Yocto'
                if description:
                    s += ': ' + description
                vul['analysis']['detail'] = s
            case _:
                raise ValueError('unknown status', id, status, description)
        




def main():
    args = parse_arguments()

    with open(args.vex_in) as f:
        vex = json.load(f)

    treated = get_treated_cves(args.cve)
    annotate_vex(treated, vex)

    if args.vex_out:
        out = open(args.vex_out, 'w')
    else:
        out = open(sys.stdout.fileno(), 'w', closefd=False)
    with out:
        json.dump(vex, out, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()

