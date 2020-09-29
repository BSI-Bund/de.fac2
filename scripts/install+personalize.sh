#!/bin/bash

GP=${GP-java -jar tools/gp.jar}

set -v
set -e

$GP -d -v \
  --uninstall defac2.cap 
  
# Install applet (User Presence Check disabled)
$GP -d -v \
  --install U2FApplet.cap \
  --create A0000006472F0001 \
  --params "010140f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664"
                                                          

# Install applet (User Presence Check enabled)
#$GP -d -v \
#  --install U2FApplet.cap \
#  --create A0000006472F0001 \
#  --params "010140f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664"

# set attestation certificate
scriptor -r "REINER SCT cyberJack RFID basis 00 00" scripts/setAttestationCert.apdu