#! /bin/bash

wget http://moz.com/top500/domains/csv/ -O top500.csv
cat top500.csv | wc -l
sudo python netGraph.py
sudo cp ./g.svg /srv/www/htdocs
