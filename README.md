# Patch-finder
[![Build Status](https://travis-ci.com/jajajasalu2/patch-finder.svg?branch=master)](https://travis-ci.com/jajajasalu2/patch-finder)
[![codecov](https://codecov.io/gh/jajajasalu2/patch-finder/branch/master/graph/badge.svg)](https://codecov.io/gh/jajajasalu2/patch-finder)

A webcrawler to extract security patches for vulnerabilities.

## Usage

For a vulnerability ID, cd into the patch-finder folder and use:

`python -m patchfinder <vuln_id>`

For Example:

`python -m patchfinder CVE-2019-7738`

Extracted patches along with the site they were retrieved from are written to `./patches.json` by default.

For other options:

`python -m patchfinder -h`

## Settings

Default settings can be altered as necessary.

For settings relevant to the scraping framework Scrapy, refer:

`patchfinder.settings.scrapy_settings`

For settings relevant to the Patch-finder, refer:

`patchfinder.settings.patchfinder_settings`

## Vulnerability identifiers

Vulnerability identifiers are notations used to identify one or more security vulnerabilities.

Identifiers that are currently recognized by the Patch-finder are:

- CVE (Common Vulnerabilities & Exposures)
- DSA (Debian Security Advisory)
- GLSA (Gentoo Linux Security Advisory)
- RHSA (Red Hat Security Advisory)

## Patch Providers

While crawling, patches or patch links are identified if they belong to a patch provider.

Providers that are currently recognized by the Patch-finder are:

- github.com
- pagure.io
- git.kernel.org
- gitlab.com
- bitbucket.org

## Parsers

Parsers are crawlers for cases other than simple webcrawling. For example, a crawler for retrieving patches from Debian or RPM packages is a parser.

Currently a parser for retrieving patches from Debian packages can be used.

Parsers can be found in `patchfinder.parsers`. Settings relevant for the operation of these parsers is in `patchfinder.settings.patchfinder_settings` (See Settings section).

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
