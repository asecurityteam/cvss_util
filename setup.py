#!/usr/bin/env python
from setuptools import setup, find_packages
import os


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='cvss-util',
      url='https://bitbucket.org/asecurityteam/cvss_util',
      packages=find_packages(),
      description=read('README'),
      long_description=read('README'),
      version=__import__('cvss_util').__version__,
      tests_require=['nose'],
      test_suite='nose.collector',
      license='BSD',
      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.4',
          'License :: OSI Approved :: BSD License',
      ],
      )
