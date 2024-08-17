#!/bin/bash

pid=$!
nc 192.168.0.2 80

trap "kill $pid" INT TERM
wait $pid
