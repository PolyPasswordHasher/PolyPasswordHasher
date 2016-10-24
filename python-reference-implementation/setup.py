#! /usr/bin/env python


from distutils.core import setup, Extension

import sys

print "This is currently test code...   You have been warned!"

# Must have Python >= 2.5 and < 3.0.   If Python version == 2.5.X, then
# simplejson is required.
if sys.version_info[0] != 2 or sys.version_info[1] < 5:
  print "Requires Python >= 2.5 and < 3.0"
  sys.exit(1)


fastpolymath_c = Extension("fastpolymath_c",
    sources=["src/fastpolymath.c"])

setup(	name="PolyPasswordHasher",
    version="0.2-alpha",
    ext_modules=[fastpolymath_c],
    description="""An early version of PolyPasswordHasher.""",
    author="Justin Cappos",
    author_email="jcappos@poly.edu",
    packages=["polypasswordhasher"]
)
