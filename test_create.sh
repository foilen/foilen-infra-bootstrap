#!/bin/bash

set -e

./create-local-release-no-tests.sh

USER_ID=$(id -u)

docker run -ti \
  --rm \
  --env HOSTFS=/hostfs/ \
  --env MACHINE_HOSTNAME=localhost.foilen-lab.com \
  --hostname localhost.foilen-lab.com \
  --network fcloud \
  --volume /etc:/hostfs/etc \
  --volume /home:/hostfs/home \
  --volume /usr/bin/docker:/usr/bin/docker \
  --volume /usr/lib/x86_64-linux-gnu/libltdl.so.7.3.1:/usr/lib/x86_64-linux-gnu/libltdl.so.7 \
  --volume /var/infra-apps/:/hostfs/var/infra-apps/ \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  foilen-infra-bootstrap:master-SNAPSHOT \
  --allDefaults --noDnsServer --debug | tee _log.txt
