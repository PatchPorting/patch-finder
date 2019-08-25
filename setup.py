import os
from setuptools import setup, find_packages

VERSION = "0.0.1"


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="patch-finder",
    version=VERSION,
    description=(
        "A webcrawler to extract patches for security vulnerabilities"
    ),
    license="BSD",
    url="http://github.com/PatchPorting/patch-finder",
    packages=find_packages(exclude=("tests", "tests.*")),
    long_description=read("README.md"),
    entry_points={
        'console_scripts': ['patchfinder = patchfinder.__main__:main']
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
    python_requires=">=3.5",
    install_requires=[
        "dicttoxml==1.7.4",
        "PyGithub==1.43",
        "Scrapy",
        "attrs>=17.4",
    ],
)
