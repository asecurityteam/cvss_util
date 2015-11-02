#!/usr/bin/env python
from setuptools import setup


setup(
      pbr=True,
      setup_requires=['pbr'],
      tests_require=['nose'],
      test_suite='nose.collector',
      )
