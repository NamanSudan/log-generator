#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

import os
import io
import runpy
from setuptools import setup, find_packages


current = os.path.realpath(os.path.dirname(__file__))

with io.open(os.path.join(current, 'README.rst'), encoding="utf-8") as f:
    long_description = f.read()

with io.open(os.path.join(current, 'HISTORY.rst'), encoding="utf-8") as f:
    history = f.read()

# Define requirements separately
install_requires = [
    'Click>=7.0',
    'PyYAML>=5.4',
    # Add other requirements from requirements.txt
]

test_requires = [
    'coverage>=5.3',
    'pytest>=6.0',
    'pytest-cov>=2.10'
]

__version__ = runpy.run_path(
    os.path.join(current, "rlog_generator", "version.py"))["__version__"]


setup(
    name='rlog-generator',
    author="Fedele Mantuano",
    author_email='mantuano.fedele@gmail.com',
    maintainer="Fedele Mantuano",
    maintainer_email='mantuano.fedele@gmail.com',
    classifiers=[
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    description="Generator of random logs for multiple types of technologies",
    entry_points={
        'console_scripts': [
            'rlog-generator=rlog_generator.cli:main',
        ],
    },
    platforms=["Linux"],
    install_requires=install_requires,
    long_description=long_description + '\n\n' + history,
    include_package_data=True,
    keywords=['log', 'generator', 'random'],
    packages=find_packages(include=['rlog_generator']),
    python_requires='>=3.6',
    extras_require={
        'test': test_requires,
    },
    tests_require=test_requires,
    url='https://github.com/WuerthPhoenix/log-generator',
    version=__version__,
    zip_safe=False,
)
