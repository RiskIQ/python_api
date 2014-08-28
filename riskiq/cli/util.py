#!/usr/bin/env python
import sys

def stdin(argv):
    parse_stdin = ('-' in argv)
    if parse_stdin:
        argv = [x for x in argv if x != '-']
        input_lines = sys.stdin.readlines()
        argv += [line.strip() for line in input_lines if line.strip()]
    return argv
