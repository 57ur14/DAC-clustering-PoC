#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from multiprocessing.connection import Client

socket_key = b'i8&*yR93Lf^&VS7B'

with Client('/tmp/cluster_sock', family='AF_UNIX', authkey=socket_key) as client:
    for i in range(10000):
        output = {'text': 'hello world', 'number': i}
        client.send(output)