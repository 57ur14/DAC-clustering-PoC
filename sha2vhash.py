# -*- coding: utf-8 -*-
"""
sha2vhash - a module for retrieving vhash for a PE-file from VirusTotal metadata

Part of D&C-Clustering-POC

Copyright (c) 2020 Sturla Høgdahl Bae

"""

import os
import json
import configparser

"""
config = configparser.ConfigParser()
config.read('config.ini')
metadata_path = config.get('feature_extraction', 'vt_metadata_path')
"""
# TODO: replace later
metadata_path = '/clusters/metadata/'

def get_vhash(sha256):
    """
    TODO: Dokumenter og kommenter kode
    """
    filepath = os.path.join(metadata_path, sha256 + '.json')
    if os.path.exists(filepath):
        with open(filepath) as infile:
            try:
                parsed = json.load(infile)
            except JSONDecodeError as e:
                print(e)
                return None
            else:
                return parsed.get('vhash')
    # Return None if vhash could not be retrieved
    return None
