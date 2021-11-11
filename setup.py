#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name="libinfoblox",
    version="2.1",
    description="Access infoblox API",
    author="Steve Weber",
    author_email="steverweber@gmail.com",
    url="https://github.com/steverweber/libinfoblox",
    download_url="https://github.com/steverweber/libinfoblox/archive/1.0.tar.gz",
    packages=find_packages(),
    install_requires=["requests", "netaddr"],
)
