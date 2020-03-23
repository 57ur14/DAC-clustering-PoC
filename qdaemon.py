#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import queue
from multiprocessing.managers import BaseManager

config = configparser.ConfigParser()
config.read('config.ini')
QUEUE_MANAGER_IP = config.get('queue_manager', 'ip')
QUEUE_MANAGER_PORT = config.getint('queue_manager', 'port')
QUEUE_MANAGER_KEY = config.get('queue_manager', 'key').encode('utf-8')

queue = queue.Queue()
class QueueManager(BaseManager):
    pass

QueueManager.register('get_queue', callable=lambda:queue)
manager = QueueManager(address=(QUEUE_MANAGER_IP, QUEUE_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
server = manager.get_server()
server.serve_forever()
