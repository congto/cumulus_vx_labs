#!/bin/bash

for interface in eth1 eth2
do
  ifdown $interface
  ifup $interface
done
