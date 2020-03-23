#!/bin/bash

if [ -n "$(ps aux | grep qdaemon | grep -v grep)" ]; then
    echo "Stopping queue daemon"
    pid=$(ps aux | grep qdaemon | grep -v grep | awk '{print $2}')
    kill $pid
fi

# Clustering daemon should quit automatically when queue killed
