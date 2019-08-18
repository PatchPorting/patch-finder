# Patch-finder
[![Build Status](https://travis-ci.com/jajajasalu2/patch-finder.svg?branch=master)](https://travis-ci.com/jajajasalu2/patch-finder)
[![codecov](https://codecov.io/gh/jajajasalu2/patch-finder/branch/master/graph/badge.svg)](https://codecov.io/gh/jajajasalu2/patch-finder)

A webcrawler to extract security patches for vulnerabilities.

## Usage

For a vulnerability ID, use:

`python patchfinder.py <vuln_id>`

For Example:

`python patchfinder.py CVE-2019-7738`

Extracted patches along with the site they were retrieved from are written to ./patches.json by default.

For other options:

`python patchfinder.py -h`

## Settings

Default settings can be altered as necessary.

For settings relevant to the scraping framework Scrapy, refer:

`patchfinder/settings/scrapy_settings.py`

For settings relevant to the Patch-finder, refer:

`patchfinder/settings/patchfinder_settings.py`

## Vulnerability identifiers

Vulnerability identifiers are notations used to identify one or more security vulnerabilities.

Identifiers that are currently recognized by the Patch-finder are:

- CVE (Common Vulnerabilities & Exposures)
- DSA (Debian Security Advisory)
- GLSA (Gentoo Linux Security Advisory)
- RHSA (Red Hat Security Advisory)

## Patch Providers:

While crawling, patches or patch links are identified if they belong to a patch provider.

Providers that are currently recognized by the Patch-finder are:

- github.com
- pagure.io
- git.kernel.org
- gitlab.com
- bitbucket.org

## Tests

To run the tests, use:

`python -m unittest discover -v tests`

Or simply:

`pytest`

## Build the docs

```
cd docs
pip install -r requirements-docs.txt
make html
```
