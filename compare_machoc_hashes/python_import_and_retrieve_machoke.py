#!/usr/bin/env python3

import subprocess

import machoke_hash

TIMEOUT = 20            # Timeout it seconds

files = [
    '/home/sturla/IJCNN_10000files/hupigon/fdc02205a4ede97ceccc207a2405b97c',
    '/home/sturla/IJCNN_10000files/small/9c06cd446dd618717529cb106f098e68',
    '/home/sturla/IJCNN_10000files/hupigon/e29773477a0c8d5f8571b16649b0dc8a',
    '/home/sturla/IJCNN_10000files/onlinegames/a9e9d287d8299db5eaea2c91567e8533',
    '/home/sturla/IJCNN_10000files/agent/7fdd280eec5bbd126f620283cc2588e4',
    '/home/sturla/IJCNN_10000files/small/c402615e42054f29aa37e53ec7db2c78',
    '/home/sturla/IJCNN_10000files/agent/e9adf3b9666bb316f1822160cd3f83f1',
    '/home/sturla/IJCNN_10000files/hupigon/c54b08a542038176c170245f15407927',
    '/home/sturla/IJCNN_10000files/zlob/79dcf9f4a4fe57867ee4d390b2bb3bc0',
    '/home/sturla/IJCNN_10000files/obfuscator/189df20510376f3b472987ea865642f5'
]

def get_machoc_r2(filepath):
    machoke = machoke_hash.Machoke(filepath, TIMEOUT, False)
    if not machoke.error:
        return machoke.mmh3_line
    else:
        return None

def get_machoc_metasm(filepath):
    try:
        metasm_process = subprocess.run(['ruby', 'machoc_hash.rb', filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT, check=True)
    except subprocess.TimeoutExpired:
        print("Timeout expired")
        return None
    else:
        machoc_hash = metasm_process.stdout.decode('utf-8')
        if machoc_hash == "\n":
            return None
        else:
            return machoc_hash

def get_machoc_all_files_r2():
    for file in files:
        machoc_hash = get_machoc_r2(file)
        if machoc_hash != None:
            print("Machoc hash from r2: " + machoc_hash)
        else:
            print("Could not retrieve machoc hash for " + file)

def get_machoc_all_files_metasm():
    for file in files:
        machoc_hash = get_machoc_metasm(file)
        if machoc_hash != None:
            print("Machoc hash from metasm: " + machoc_hash)
        else:
            print("Could not retrieve machoc hash for " + file)

get_machoc_all_files_r2()      
# Runtime: 1 minute and 17,779 seconds (77,779 seconds in total)

#get_machoc_all_files_metasm()  
# Runtime: 37,037 seconds

# Notes
# Metasm seems to process files 110 % faster than r2
# Both succeeded at 8 of 10 files
# But with an average speed of 3.7 seconds per file,
# metasm is not impressive either