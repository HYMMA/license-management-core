"""Setup shim for building platform-tagged wheels.

The package is pure Python; the platform-specific part is the libhymmalm
binary that CI copies into the package directory before building each
wheel with an explicit platform tag:

    python setup.py bdist_wheel --plat-name manylinux... / win_amd64 / macosx...

which yields py3-none-<platform> wheels (one per OS/arch, carrying the
right native library). The sdist stays pure — installing from source means
providing the native library yourself (build it with cmake and set
HYMMALM_LIB or drop it next to the package)."""
from setuptools import setup

setup()
