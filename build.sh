#!/usr/bin/env bash

set -o errexit
set -o nounset

BUILD_DIR="${HOME}/rpmbuild"
SOURCES_DIR="${BUILD_DIR}/SOURCES"
WORK_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"

VERSION_RELEASE="2020.08.06.1"

[[ "${VERSION_RELEASE}" =~ ([0-9]{4}\.[0-9]{2}\.[0-9]{2})(\.([0-9]+)) ]]
VERSION="${BASH_REMATCH[1]}"
RELEASE="${BASH_REMATCH[3]}"

mkdir -p "${SOURCES_DIR}"
tar --create --file "${SOURCES_DIR}/SynAcktor-${VERSION}-${RELEASE}.noarch.tar.gz" --gzip --directory "${WORK_DIR}/source" .
rpmbuild -bb "${WORK_DIR}/SynAcktor.spec" --define "_version ${VERSION}" --define "_release ${RELEASE}"
