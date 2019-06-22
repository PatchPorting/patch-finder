# patch-finder
A tool to find security patches from across the web.

## Usage
`python patchfinder.py <vuln_id>`

Example:
`python patchfinder.py CVE-2019-7738`
The patches output in ./patches.json

For other options:
`python patchfinder.py -h`

## Run the tests with
`python -m unittest discover  -v tests`
