#!/bin/bash

php -S 0.0.0.0:8081 2> /dev/null &

PHPID=$!

# wait for php
sleep 2

while true; do
    echo 'Running bot'
    node bot.js
    echo 'waiting 1 minute'
    sleep 60 #seconds
done

kill $PHPID
