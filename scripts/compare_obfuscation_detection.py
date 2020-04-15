#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pefile
import peutils

import unpacking

total_files = 0
divide_detected = 0
section_names_detected = 0
diec_detected = 0
section_properties_detected = 0
peid_detected = 0

with open('supporting_files/UserDB.TXT', 'rt', encoding='iso-8859-15') as f: 
    sig_data = f.read()
signatures = peutils.SignatureDatabase(data=sig_data)

with open('files_random.txt') as infile:
    lines = infile.read().splitlines()
    for line in lines:
        filepath, family = line.split(' ')
        pe = pefile.PE(filepath)
        pe.parse_data_directories()
        warnings = pe.get_warnings()
        total_files += 1
        peid_match = signatures.match(pe)
        if peid_match is not None:
            peid_detected += 1
        if unpacking.detect_obfuscation(filepath, pe, warnings) != {'type': 'none'}:
            divide_detected += 1
        
        if unpacking.detect_obfuscation_by_section_names(pe) != {'type': 'none'}:
            section_names_detected += 1
        if unpacking.detect_obfuscation_by_diec(filepath) != {'type': 'none'}:
            diec_detected += 1
        if unpacking.detect_obfuscation_by_section_properties(pe, warnings) != {'type': 'none'}:
            section_properties_detected += 1
        

print("Total files processed: " + str(total_files))
print("Files detected to be packed by divide and conquer: " + str(divide_detected))
print("Files detected to be packed using section names: " + str(section_names_detected))
print("Files detected to be packed using DetectItEasy: " + str(diec_detected))
print("Files detected to be packed using section properties: " + str(section_properties_detected))
print("Files detected to be packed using PEiD: " + str(peid_detected))