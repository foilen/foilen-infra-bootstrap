#!/bin/bash

set -e

RUN_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $RUN_PATH

echo ----[ Upload docker image ]----
DOCKER_IMAGE=foilen-infra-bootstrap:$VERSION
docker login
docker tag $DOCKER_IMAGE foilen/$DOCKER_IMAGE
docker tag $DOCKER_IMAGE foilen/foilen-infra-bootstrap:latest
docker push foilen/$DOCKER_IMAGE
docker push foilen/foilen-infra-bootstrap:latest
