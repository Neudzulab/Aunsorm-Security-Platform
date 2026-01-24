#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == "" ]]; then
  echo "Usage: $0 <package|install|approve|commit|upgrade>" >&2
  echo "Required env: FABRIC_CHANNEL FABRIC_CHAINCODE FABRIC_CC_VERSION FABRIC_CC_SEQUENCE" >&2
  echo "Optional env: FABRIC_CC_LABEL FABRIC_CC_PATH FABRIC_CC_LANG FABRIC_ORDERER FABRIC_PEER_ADDRESS" >&2
  echo "Optional env: FABRIC_TLS_ROOTCERT FABRIC_ORDERER_TLS_CA FABRIC_INIT_REQUIRED" >&2
  exit 1
fi

: "${FABRIC_CHANNEL:?FABRIC_CHANNEL is required}"
: "${FABRIC_CHAINCODE:?FABRIC_CHAINCODE is required}"
: "${FABRIC_CC_VERSION:?FABRIC_CC_VERSION is required}"
: "${FABRIC_CC_SEQUENCE:?FABRIC_CC_SEQUENCE is required}"

FABRIC_CC_LABEL=${FABRIC_CC_LABEL:-"${FABRIC_CHAINCODE}_${FABRIC_CC_VERSION}"}
FABRIC_CC_PATH=${FABRIC_CC_PATH:-"./apps/fabric/chaincode/did_registry"}
FABRIC_CC_LANG=${FABRIC_CC_LANG:-"golang"}
FABRIC_INIT_REQUIRED=${FABRIC_INIT_REQUIRED:-"false"}
FABRIC_ORDERER=${FABRIC_ORDERER:-""}
FABRIC_PEER_ADDRESS=${FABRIC_PEER_ADDRESS:-""}
FABRIC_TLS_ROOTCERT=${FABRIC_TLS_ROOTCERT:-""}
FABRIC_ORDERER_TLS_CA=${FABRIC_ORDERER_TLS_CA:-""}

peer_args=()
if [[ -n ${FABRIC_PEER_ADDRESS} ]]; then
  peer_args+=(--peerAddresses "${FABRIC_PEER_ADDRESS}")
fi
if [[ -n ${FABRIC_TLS_ROOTCERT} ]]; then
  peer_args+=(--tlsRootCertFiles "${FABRIC_TLS_ROOTCERT}")
fi

orderer_args=()
if [[ -n ${FABRIC_ORDERER} ]]; then
  orderer_args+=(--orderer "${FABRIC_ORDERER}")
fi
if [[ -n ${FABRIC_ORDERER_TLS_CA} ]]; then
  orderer_args+=(--tls --cafile "${FABRIC_ORDERER_TLS_CA}")
fi

case "$1" in
  package)
    peer lifecycle chaincode package "${FABRIC_CC_LABEL}.tar.gz" \
      --path "${FABRIC_CC_PATH}" \
      --lang "${FABRIC_CC_LANG}" \
      --label "${FABRIC_CC_LABEL}"
    ;;
  install)
    peer lifecycle chaincode install "${FABRIC_CC_LABEL}.tar.gz"
    ;;
  approve)
    package_id=$(peer lifecycle chaincode queryinstalled | \
      awk -v label="${FABRIC_CC_LABEL}" '$0 ~ label {print $3}' | tr -d ',')
    if [[ -z ${package_id} ]]; then
      echo "Package ID not found for label ${FABRIC_CC_LABEL}" >&2
      exit 1
    fi
    peer lifecycle chaincode approveformyorg \
      --channelID "${FABRIC_CHANNEL}" \
      --name "${FABRIC_CHAINCODE}" \
      --version "${FABRIC_CC_VERSION}" \
      --sequence "${FABRIC_CC_SEQUENCE}" \
      --package-id "${package_id}" \
      --init-required "${FABRIC_INIT_REQUIRED}" \
      "${orderer_args[@]}"
    ;;
  commit)
    peer lifecycle chaincode commit \
      --channelID "${FABRIC_CHANNEL}" \
      --name "${FABRIC_CHAINCODE}" \
      --version "${FABRIC_CC_VERSION}" \
      --sequence "${FABRIC_CC_SEQUENCE}" \
      --init-required "${FABRIC_INIT_REQUIRED}" \
      "${peer_args[@]}" \
      "${orderer_args[@]}"
    ;;
  upgrade)
    peer lifecycle chaincode commit \
      --channelID "${FABRIC_CHANNEL}" \
      --name "${FABRIC_CHAINCODE}" \
      --version "${FABRIC_CC_VERSION}" \
      --sequence "${FABRIC_CC_SEQUENCE}" \
      --init-required "${FABRIC_INIT_REQUIRED}" \
      "${peer_args[@]}" \
      "${orderer_args[@]}"
    ;;
  *)
    echo "Unknown command: $1" >&2
    exit 1
    ;;
esac
