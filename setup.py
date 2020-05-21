#!/usr/bin/env python3
"""The setup script."""

import setuptools

requirements = [
    "Flask~=1.0",
    "requests~=2.0",
]

packages = setuptools.find_packages(where="./", include=["powerdns_auth_proxy"])
if not packages:
    raise ValueError("No packages detected.")

setuptools.setup(
    name="powerdns-auth-proxy",
    version=0.1,
    description="",
    long_description="",
    author="Catalyst OpsDev",
    author_email="opsdev@catalyst.net.nz",
    url="https://github.com/catalyst/powerdns-auth-proxy",
    packages=packages,
    install_requires=requirements,
    zip_safe=False,
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
)

