#!/bin/bash

DOCKER_MANAGER_VERSION=$1
uiApiBaseUrl=$2
uiApiUserId=$3
uiApiUserKey=$4
machineName=$5

USERNAME=infra_docker_manager
DATA_PATH=/home/$USERNAME/data
INTERNAL_DATABASE_PATH=$DATA_PATH/db
PERSISTED_CONFIG_PATH=$DATA_PATH/persistedConfig
IMAGE_BUILD_PATH=$DATA_PATH/imageBuild
mkdir -p /hostfs/$INTERNAL_DATABASE_PATH /hostfs/$PERSISTED_CONFIG_PATH /hostfs/$IMAGE_BUILD_PATH

# Create config
cat > /hostfs/$DATA_PATH/config.json << _EOF
{
  "internalDatabasePath" : "/data/db",
  "persistedConfigPath" : "/data/persistedConfig",
  "imageBuildPath" : "/data/imageBuild"
}
_EOF

# Create machinesetup
cat > /hostfs/$DATA_PATH/persistedConfig/machineSetup.json << _EOF
{
	"uiApiBaseUrl" : "$uiApiBaseUrl", 
	"uiApiUserId" : "$uiApiUserId",
	"uiApiUserKey" : "$uiApiUserKey",
	"machineName" : "$machineName"
}
_EOF

# Execute
docker run \
  --detach \
  --restart always \
  --env HOSTFS=/hostfs/ \
  --env CONFIG_FILE=/data/config.json \
  --volume $DATA_PATH:/data \
  --volume /:/hostfs/ \
  --volume /usr/bin/docker:/usr/bin/docker \
  --volume /usr/lib/x86_64-linux-gnu/libltdl.so.7.3.1:/usr/lib/x86_64-linux-gnu/libltdl.so.7 \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  --hostname $machineName \
  --workdir /data \
  --name infra_docker_manager \
  foilen/foilen-infra-docker-manager:$DOCKER_MANAGER_VERSION --debug
