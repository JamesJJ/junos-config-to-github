#!/usr/bin/env bash
set -euo pipefail

SERVER="${1:-http://localhost:8000}"

CONFIG='set version 25.4R1-S1.4
set system host-name mock-test-test-test
set system root-authentication encrypted-password "$6$FAKE$notarealpasswordhash"
set system services ssh
set groups CREDS interfaces pp0 unit 0 ppp-options chap default-chap-secret "$9$fakeSecret123"
set groups CREDS interfaces pp0 unit 0 ppp-options chap local-name "testuser@example.net"
set groups CREDS interfaces pp0 unit 0 ppp-options pap local-password "$9$fakePassword456"
set interfaces ge-0/0/0 unit 0 encapsulation ppp-over-ether
set interfaces irb unit 0 family inet address 192.168.1.1/24
set security zones security-zone TRUST interfaces irb.0
set security policies default-policy deny-all'

curl -v -X PUT "${SERVER}/archive" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @<(echo "$CONFIG" | gzip)
