#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from multiprocessing.connection import Listener, wait

socket_key = b'i8&*yR93Lf^&VS7B'

while True:
    with Listener(address='/tmp/cluster_sock', family='AF_UNIX', authkey=socket_key) as listener:
        with listener.accept() as conn:
            while conn.poll(1):
                try:
                    input = conn.recv()
                    # TODO: Work on the input
                    print(input)
                except EOFError:
                    break
    print("Done analysing. Waiting for new input..")