import argparse
from patchfinder.context import CVE

parser = argparse.ArgumentParser(description='Finds patches for a vulnerability id.')
parser.add_argument('--cve')

args = parser.parse_args()
cve = CVE(args.cve)
for entrypoint in cve.entrypoint_URLs():
    print(entrypoint)
