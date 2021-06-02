# About

To bootstrap the infrastructure system. It can create a new cluster or join an existing one.

# Bootstrap a node

## New cluster

### Prerequisite

On Ubuntu 16.04:

```
# Install base applications
cd /tmp
wget https://deploy.foilen.com/docker-sudo/docker-sudo_1.3.2_amd64.deb
dpkg -i docker-sudo_1.3.2_amd64.deb

apt update && \
apt -y dist-upgrade && \
apt -y autoremove

apt install -y haveged docker.io

# Add swap memory (5G in 5 1G files. Useful if you want to easily remove some G later)
for i in {1..5}; do
  SWAP_FILE=/var/swap.$i
  echo Generating $SWAP_FILE
  fallocate -l 1G $SWAP_FILE
  chmod 600 $SWAP_FILE
  /sbin/mkswap $SWAP_FILE
  echo $SWAP_FILE swap swap defaults 0 0 >> /etc/fstab
  /sbin/swapon $SWAP_FILE
done

# Enable SSHD password authentication
if egrep '^PasswordAuthentication no$' /etc/ssh/sshd_config > /dev/null ; then
  echo Enabling SSHD password authentication
  sed 's/^PasswordAuthentication no$/#PasswordAuthentication no/g' /etc/ssh/sshd_config > /etc/ssh/sshd_config.tmp
  mv /etc/ssh/sshd_config.tmp /etc/ssh/sshd_config
  service sshd restart
fi
```

### Use in Interactive Mode

```
docker run -ti \
  --rm \
  --env HOSTFS=/hostfs/ \
  --env MACHINE_HOSTNAME=$(hostname -f) \
  --hostname $(hostname -f) \
  --volume /etc:/hostfs/etc \
  --volume /home:/hostfs/home \
  --volume /usr/bin/docker:/usr/bin/docker \
  --volume /usr/lib/x86_64-linux-gnu/libltdl.so.7.3.1:/usr/lib/x86_64-linux-gnu/libltdl.so.7 \
  --volume /var/infra-apps/:/hostfs/var/infra-apps/ \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  foilen/foilen-infra-bootstrap:latest
```

It will create the *fcloud* network and ask you to use it. You can then run:

```
docker run -ti \
  --rm \
  --env HOSTFS=/hostfs/ \
  --env MACHINE_HOSTNAME=$(hostname -f) \
  --hostname $(hostname -f) \
  --network fcloud \
  --volume /etc:/hostfs/etc \
  --volume /home:/hostfs/home \
  --volume /usr/bin/docker:/usr/bin/docker \
  --volume /usr/lib/x86_64-linux-gnu/libltdl.so.7.3.1:/usr/lib/x86_64-linux-gnu/libltdl.so.7 \
  --volume /var/infra-apps/:/hostfs/var/infra-apps/ \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  foilen/foilen-infra-bootstrap:latest
```

### Generate questions in a file and feed it back

Generate a JSON file with all questions and answers if you do not want to use the interactive mode:

```
DATA_DIR=$(mktemp -d)
cd $DATA_DIR

docker run -ti \
  --rm \
  --env HOSTFS=/hostfs/ \
  --env MACHINE_HOSTNAME=$(hostname -f) \
  --hostname $(hostname -f) \
  --volume $DATA_DIR:/data \
  --volume /etc:/hostfs/etc \
  --volume /home:/hostfs/home \
  --volume /usr/bin/docker:/usr/bin/docker \
  --volume /usr/lib/x86_64-linux-gnu/libltdl.so.7.3.1:/usr/lib/x86_64-linux-gnu/libltdl.so.7 \
  --volume /var/infra-apps/:/hostfs/var/infra-apps/ \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  foilen/foilen-infra-bootstrap:latest \
  --genJsonAnswers --jsonAnswerFile /data/bootstrap.json
```

Edit the file.

Execute the bootstrap using the answer file:

```
docker run -ti \
  --rm \
  --env HOSTFS=/hostfs/ \
  --env MACHINE_HOSTNAME=$(hostname -f) \
  --hostname $(hostname -f) \
  --network fcloud \
  --volume $DATA_DIR:/data \
  --volume /etc:/hostfs/etc \
  --volume /home:/hostfs/home \
  --volume /usr/bin/docker:/usr/bin/docker \
  --volume /usr/lib/x86_64-linux-gnu/libltdl.so.7.3.1:/usr/lib/x86_64-linux-gnu/libltdl.so.7 \
  --volume /var/infra-apps/:/hostfs/var/infra-apps/ \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  foilen/foilen-infra-bootstrap:latest \
  --jsonAnswerFile /data/bootstrap.json --startDockerManager --info | tee bootstrap.log
```

## Join a cluster

### From the UI

* Go in your Infra UI
* Go in Infrastructure > Machine - Bootstrap
* Choose your machine
* Copy the commands to run as root in your shell
