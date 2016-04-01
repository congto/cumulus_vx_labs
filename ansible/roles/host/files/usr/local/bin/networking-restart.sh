#!/bin/bash

for interface in `ifquery --list | egrep -o "eth[^0](\.[0-9]+)?"`
do
  ifdown $interface
  ifup $interface
done
