#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import multiprocessing
import queue
import signal
from multiprocessing.managers import BaseManager

# Retreive configuration
config = configparser.ConfigParser()
config.read('config.ini')
PRINT_PROGRESS = config.getboolean('clustering', 'print_progress')
QUEUE_MANAGER_IP = config.get('queue_managers', 'ip')
EXTRACTION_MANAGER_PORT = config.getint('queue_managers', 'extraction_port')
CLUSTER_MANAGER_PORT = config.getint('queue_managers', 'clustering_port')
QUEUE_MANAGER_KEY = config.get('queue_managers', 'key').encode('utf-8')
QUEUE_TIMEOUT = config.getint('queue_managers', 'timeout')

# Define queue manager class
class QueueManager(BaseManager):
    pass
QueueManager.register('get_queue')

def sigint_handler(signum, frame):
    """
    Do not quit immediately if recieving SIGINT.
    In stead, modify "continue_working" such that the script 
    will stop attempting to retrieve new items from the queue
    and rather save variables to pickles.
    """
    print("SIGINT recieved. Quitting and saving state after processing the current file.")
    global continue_working
    continue_working = False

def feature_extraction_worker():
    # Import feature_extraction separately for each thread/process to 
    # avoid race condition (each thread will have separate tmp directory)
    import feature_extraction

    # Connect to feature extraction queue and clustering queue
    extraction_manager = QueueManager(address=(QUEUE_MANAGER_IP, EXTRACTION_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
    cluster_manager = QueueManager(address=(QUEUE_MANAGER_IP, CLUSTER_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
    try:
        extraction_manager.connect()
        cluster_manager.connect()
    except:
        print("Cannot connect to queue manager. Please check the configuration.")
    else:
        extraction_queue = extraction_manager.get_queue()
        cluster_queue = cluster_manager.get_queue()

        global continue_working
        while continue_working == True:
            try:
                file_to_cluster = extraction_queue.get(timeout=QUEUE_TIMEOUT)
            except EOFError:
                print("Queue not available. Please check if the feature extraction queue manager is still running.")
                break
            except queue.Empty:
                # Stop if queue is empty and SIGINT has been sent
                if continue_working == True:
                    print("Waiting for files to extract")
                    continue
                else:
                    break
            else:
                result = feature_extraction.analyse_file(file_to_cluster['path'], family=file_to_cluster['family'], incoming=True)
                send_to_clustering(result, cluster_queue)

def send_to_clustering(fileinfo, cluster_queue):
    """
    Recursively send files to the clustering queue.
    Send contained files first since the parents can be clustered
    based on the properties of their children.
    """
    for value in fileinfo['contained_pe_fileinfo'].values():
        send_to_clustering(value, cluster_queue)
    fileinfo.pop('contained_pe_fileinfo')
    cluster_queue.put(fileinfo)

# If main script (not another thread/process)
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Start workers that extract features and add them to clustering queue.')
    parser.add_argument('-N', '--number-of-workers', help='Integer specifying the number of extraction threads threads')
    args = parser.parse_args()

    number_of_workers = multiprocessing.cpu_count()

    if args.number_of_workers is not None:
        number_of_workers = int(args.number_of_workers)

    continue_working = True
    # Create SIGINT handler to avoid shutting down while extracting features
    signal.signal(signal.SIGINT, sigint_handler)

    # Create a thread that retrieves files from feature extraction queue,
    # extracts their features and adds them to the clustering queue.
    feature_extraction_processes = []
    for i in range(number_of_workers):
        p = multiprocessing.Process(target=feature_extraction_worker, daemon=True)
        p.start()
        feature_extraction_processes.append(p)

    for proc in feature_extraction_processes:
        # Wait until all feature extraction processes have quit
        proc.join()
    print("Extractor workers done")