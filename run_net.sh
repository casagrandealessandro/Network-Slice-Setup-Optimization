#!/bin/bash
if ! command -v python3.9 >/dev/null 2>&1
then
    return_code = $(python3 ./topology.py)
else
    return_code = $(python3.9 ./topology.py)
fi

if [[ $return_code -eq 1 ]]; then
    mn -c
    docker stop $(docker ps -a -q)
    docker rm $(docker ps -a -q)
fi