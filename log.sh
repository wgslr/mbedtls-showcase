#!/bin/bash

stty -F /dev/ttyACM0 115200
ts '%FT%.T' < /dev/ttyACM0 | tee -a tty.log
