# -*- coding: utf-8 -*-
"""
sha2vhash - a module for retrieving vhash for a PE-file from VirusTotal metadata

Part of D&C-Clustering-POC

Copyright (c) 2020 Sturla Høgdahl Bae

"""

import os
import json
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
metadata_path = config.get('feature_extraction', 'vt_metadata_path')

def get_vhash(sha256):
    """
    Retrieve the vhash of a file
    """
    # Assume that the metadata file is named <sha256digest>.json,
    # located in the folder specified in the configuration.
    filepath = os.path.join(metadata_path, sha256 + '.json')
    if os.path.exists(filepath):
        # If the file exists
        with open(filepath) as infile:
            try:
                # Parse the json file
                parsed = json.load(infile)
            except json.JSONDecodeError as e:
                print(e)
                return None
            else:
                # Return the vhash of the file
                return parsed.get('vhash')
    # Return None if vhash could not be retrieved
    return None
