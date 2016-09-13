#!/bin/env python

import os
import unittest
from framework import ColoredTextTestRunner

if __name__ == '__main__':
    try:
        verbose = int(os.getenv("V", 0))
    except:
        verbose = 0
    unittest.main(testRunner=ColoredTextTestRunner, module=None, verbosity=verbose)
