#!/bin/bash

for interface in `ifquery --list | egrep -o "eth[^0](\.[0-9]+)?|enp0s[0-2,4-9](\.[0-9]+)?" | sort | uniq`
do
  ifdown $interface
  ifup $interface
done
