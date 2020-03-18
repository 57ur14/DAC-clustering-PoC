#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from multiprocessing.managers import BaseManager
import queue

queue = queue.Queue()
class QueueManager(BaseManager):
    pass

queue_key = b'i8&*yR93Lf^&VS7B'

QueueManager.register('get_queue', callable=lambda:queue)
manager = QueueManager(address=('', 33851), authkey=queue_key)
server = manager.get_server()
server.serve_forever()
