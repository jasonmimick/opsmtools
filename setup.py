#!/usr/bin/env python

from setuptools import setup

setup(name='opsmtools',
      version='0.0.2',
      description='MongoDB Ops Manager API helper',
      author='Jason Mimick',
      author_email='jason.mimick@mongodb.com',
      url='http://github.com/jasonmimick/opsmtools',
      entry_points={
          "console_scripts":[
              "opsmtools=opsmtools"
          ]
      },
      py_modules=['opsmtools'],
      install_requires=[
      'requests>=2.9.1',
      'terminaltables>=2.1.0'
]
)
