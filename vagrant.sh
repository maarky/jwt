#!/bin/bash

apt-get update
apt-get install -y php7.2-cli php7.2-mbstring php7.2-xml php7.2-zip  git zip

php -r "readfile('https://getcomposer.org/installer');" > composer-setup.php
php composer-setup.php --install-dir=/usr/local/bin --filename=composer
php -r "unlink('composer-setup.php');"

/bin/dd if=/dev/zero of=/var/swap.1 bs=1M count=1024
/sbin/mkswap /var/swap.1
/sbin/swapon /var/swap.1

cd /vagrant

composer install

apt-get install php-xdebug

cat > /etc/php/7.2/cli/conf.d/30-xdebug_settings.ini << EOF
xdebug.remote_enable=1
xdebug.remote_handler=dbgp
xdebug.remote_connect_back=1
error_reporting=E_ALL & ~E_NOTICE & ~E_STRICT & ~E_DEPRECATED
EOF

chgrp vagrant /home/ubuntu
chmod 775 /home/ubuntu/