#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import queue
from multiprocessing.managers import BaseManager

config = configparser.ConfigParser()
config.read('config.ini')
QUEUE_MANAGER_IP = config.get('queue_managers', 'ip')
JOB_MANAGER_PORT = config.getint('queue_managers', 'job_port')
QUEUE_MANAGER_KEY = config.get('queue_managers', 'key').encode('utf-8')

# Define queue manager class
class QueueManager(BaseManager):
    pass
QueueManager.register('get_queue')


# Parse arguments
parser = argparse.ArgumentParser(description='Process a file; Extract features and send to clustering.')
parser.add_argument('-P', '--path', help='Path to a single file that should be processed.')
parser.add_argument('-F', '--family', help='Malware family the single file belongs to (optional)')
parser.add_argument('-L', '--list', help='Path to a file containing paths to files on separate lines')
parser.add_argument('-C', '--combined-list', help='Path to a file where each line consists of <path> <family>. Path must not contain any spaces.')
args = parser.parse_args()

# Fill list with files that should be sent to analysis
files_for_analysis = []
if args.path is not None:
    # Process single specified file
    files_for_analysis.append({'path': args.path, 'family': args.family})
elif args.list is not None:
    # Load paths from file and process files
    with open(args.list, 'r') as infile:
        lines = infile.read().splitlines()
        for line in lines:
            files_for_analysis.append({'path': line, 'family': None})
elif args.combined_list is not None:
    # Load paths and families from file and process the files
    with open(args.combined_list, 'r') as infile:
        lines = infile.read().splitlines()
        for line in lines:
            path, fam = line.split(' ')
            files_for_analysis.append({'path': path, 'family': fam})
else:
    # Print help if no arguments were specified
    print("At least one of the following combinations must be supplied: (-P <path> [-F <family>]) | -L <path to list> | -C <path to combined-list>")
    parser.print_help()

if not files_for_analysis:
        print("No files to analyse")
else:
    add_files_for_extraction(files_for_analysis)
    print("Done adding files to queue")