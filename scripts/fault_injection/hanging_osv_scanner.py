#!/usr/bin/env python3
"""Fault-injection stand-in for osv-scanner that never answers.

Used by demonstration scenario 06 and the regression tests to prove that a
scanner timeout produces an INDETERMINATE decision instead of a clean result.
It performs no network access and touches no files.
"""

import sys
import time

if "--version" in sys.argv:
    print("osv-scanner version: fault-injection-stub")
    sys.exit(0)
time.sleep(300)
