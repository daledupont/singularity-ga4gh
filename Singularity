# bootstrap from docker ubuntu image
BootStrap: docker
From: ubuntu:latest

%setup

    # copy files into singularity container root
    cp -r config $SINGULARITY_ROOTFS
 
%post
    apt-get update  --fix-missing

    apt-get install -y tar git curl libcurl4-openssl-dev wget dialog \
    net-tools build-essential python python-dev python-distribute \
    python-pip zlib1g-dev libxslt1-dev libffi-dev libssl-dev

    mkdir -p /srv/ga4gh-server

    #mv /ga4gh-server /srv

    git clone https://github.com/Bio-Core/ga4gh-server.git /srv/ga4gh-server

    # copy the modified files
    mv /config/requirements.txt  /srv/ga4gh-server/requirements.txt
    mv /config/frontend.py  /srv/ga4gh-server/ga4gh/server/frontend.py
    mv /config/serverconfig.py  /srv/ga4gh-server/ga4gh/server/serverconfig.py
    mv /config/application.wsgi  /srv/ga4gh-server/deploy/application.wsgi
    mv /config/001-ga4gh.conf  /srv/ga4gh-server/deploy/001-ga4gh.conf
    mv /config/dataPrep.py  /srv/ga4gh-server/dataPrep.py
    mv /config/config.py    /srv/ga4gh-server/deploy/config.py
    mv /config/ports.conf /srv/ga4gh-server/deploy/ports.conf
    mv /config/client_secrets.json /srv/ga4gh-server/client_secrets.json

    rm -r /config

    # install python package requirements
    pip install -r /srv/ga4gh-server/requirements.txt

    pip install /srv/ga4gh-server

    # ga4gh server setup
    cp /srv/ga4gh-server/deploy/application.wsgi /srv/application.wsgi
    cp /srv/ga4gh-server/deploy/config.py /srv/config.py

    # prepare sample/compliance data
    cd /srv/ga4gh-server/scripts

    python prepare_compliance_data.py -o /srv/ga4gh-compliance-data

%runscript

    exec ga4gh_server
