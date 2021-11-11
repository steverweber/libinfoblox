#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name="libinfoblox",
    version="2.2",
    download_url="https://github.com/steverweber/libinfoblox/archive/2.2.tar.gz",
    description="Access infoblox API",
    author="Steve Weber",
    author_email="steverweber@gmail.com",
    url="https://github.com/steverweber/libinfoblox",
    packages=find_packages(),
    install_requires=["requests", "netaddr"],
)
