#!/bin/sh
set -eu
umask 077
cp /artifact/index.js /modules/index.js.new
mv /modules/index.js.new /modules/index.js
