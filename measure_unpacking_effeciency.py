#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unpacking

with open('files_random.txt') as infile:
    lines = infile.read().splitlines()
    for line in lines:
        filepath, family = line.split(' ')
        obfuscation = unpacking.detect_obfuscation_by_diec(filepath)

