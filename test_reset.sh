#!/bin/bash

RUN_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $RUN_PATH

docker stop infra_redirector_exit infra_web-vm-18 infra_ui infra_login infra_ui_db infra_login_db infra_bind9 infra_docker_manager infra_web-localhost_foilen-lab_com infra_redirector_entry infra_ui_db_manager
docker rm infra_redirector_exit infra_web-vm-18 infra_ui infra_login infra_ui_db infra_login_db infra_bind9 infra_docker_manager infra_web-localhost_foilen-lab_com infra_redirector_entry infra_ui_db_manager

rm -rf _logs _log.txt

sudo deluser infra_bind9
sudo deluser infra_login
sudo deluser infra_login_db
sudo deluser infra_ui
sudo deluser infra_ui_db
sudo deluser infra_web
sudo deluser infra_docker_manager
sudo deluser infra_url_redirection

sudo groupdel infra_bind9
sudo groupdel infra_login
sudo groupdel infra_login_db
sudo groupdel infra_ui
sudo groupdel infra_ui_db
sudo groupdel infra_web
sudo groupdel infra_docker_manager
sudo groupdel infra_url_redirection

sudo rm -rf /home/infra_* /var/infra-apps/ /var/infra-endpoints/
