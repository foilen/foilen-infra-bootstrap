#!/bin/bash

RUN_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $RUN_PATH

mkdir -p _logs
cd _logs

for i in $(docker ps -a | tr -s ' ' | cut -d' ' -f 2); do
	docker cp $i:/var/log $i
done
