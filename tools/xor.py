#!/usr/bin/env python3
import sys
data = open(sys.argv[1], 'rb').read()
open(sys.argv[2], 'wb').write(bytes(b ^ 0xAB for b in data))
