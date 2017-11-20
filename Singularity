# bootstrap from docker ubuntu image
BootStrap: docker
From: ubuntu:latest

%setup

    # copy files into singularity container root
    cp -r /home/vagrant/candig-deploy/ga4gh/ga4gh-server $SINGULARITY_ROOTFS
 
%post

    # at this point we're at the root(/) of filesystem in the container

    # install required applications
    apt-get update  --fix-missing

    apt-get install -y tar git curl libcurl4-openssl-dev wget dialog \
    net-tools build-essential python python-dev python-distribute \
    python-pip zlib1g-dev libxslt1-dev libffi-dev libssl-dev

    # ga4gh server setup
    # a2enmod wsgi

    # mkdir /var/cache/apache2/python-egg-cache && \
    # chown www-data:www-data /var/cache/apache2/python-egg-cache/

    mkdir -p /srv/ga4gh-server

    mv /ga4gh-server /srv

    # install python package requirements
    pip install -r /srv/ga4gh-server/requirements.txt

    pip install /srv/ga4gh-server

    # ga4gh server setup
    #cp /srv/ga4gh-server/deploy/ports.conf /etc/apache2/ports.conf
    #cp /srv/ga4gh-server/deploy/001-ga4gh.conf /etc/apache2/sites-available/001-ga4gh.conf
    cp /srv/ga4gh-server/deploy/application.wsgi /srv/application.wsgi
    cp /srv/ga4gh-server/deploy/config.py /srv/config.py

    #cd /etc/apache2/sites-enabled
    #a2dissite 000-default
    #a2ensite 001-ga4gh

    # prepare sample/compliance data
    cd /srv/ga4gh-server/scripts

    python prepare_compliance_data.py -o ../../ga4gh-compliance-data
    # python /srv/ga4gh-server/dataPrep.py default

%runscript

    exec ga4gh_server
    #exec /usr/sbin/apache2ctl start
