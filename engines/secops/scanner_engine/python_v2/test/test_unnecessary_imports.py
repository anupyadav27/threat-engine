# Test script to trigger unnecessary_imports_should_be_removed rule only

import os
import sys
import math

def my_function():
    print(math.sqrt(4))

# 'os' and 'sys' are imported but never used
