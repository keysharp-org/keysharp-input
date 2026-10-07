#!/usr/bin/env bash
# Builds the unsigned Launchpad source uploads for this project, one per Ubuntu series, into
# OUTPUT_DIR. The upstream tarball is the committed HEAD with its submodules; debian/ is
# packaging/debian as it stands.
#
# Environment:
#   VERSION        upstream version; defaults to the CMake project version
#   SERIES         Ubuntu series to build for (default: "noble resolute")
#   PPA_REVISION   positive packaging revision N in <version>-1~<series>N
#   PPA            owner/name; when that PPA already holds this version's upstream tarball, it is
#                  reused, because Launchpad accepts no other file under the same name
#   OUTPUT_DIR     default: dist/ppa
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="${ROOT}/packaging/ppa"
NAME="$(sed -n 's/^Source: //p' "${ROOT}/packaging/debian/control")"
VERSION="${VERSION:-$(sed -n "/^project(${NAME}/,/LANGUAGES/s/^[[:space:]]*VERSION \([0-9.]*\)$/\1/p" "${ROOT}/CMakeLists.txt")}"
SERIES="${SERIES:-noble resolute}"
PPA_REVISION="${PPA_REVISION:-1}"
PPA="${PPA:-}"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT}/dist/ppa}"

[[ "${VERSION}" =~ ^[0-9]+(\.[0-9]+){2}$ ]] || { echo "Invalid ${NAME} version: ${VERSION}" >&2; exit 1; }
[[ "${SERIES}" =~ ^[a-z]+( [a-z]+)*$ && "${PPA_REVISION}" =~ ^[1-9][0-9]*$ ]] \
  || { echo "Invalid SERIES or PPA_REVISION." >&2; exit 1; }

epoch="$(git -C "${ROOT}" log -1 --format=%ct HEAD)"
maintainer="$(sed -n 's/^Maintainer: //p' "${ROOT}/packaging/debian/control")"
work="$(mktemp -d)"
trap 'rm -rf -- "${work}"' EXIT
orig_name="${NAME}_${VERSION}.orig.tar.xz"
orig="${OUTPUT_DIR}/${orig_name}"
mkdir -p "${OUTPUT_DIR}"
rm -f -- "${OUTPUT_DIR}/${NAME}_${VERSION}"[-.]*

reused_orig=false
if [[ -n "${PPA}" ]] && url="$(python3 "${HERE}/launchpad.py" orig-url "${PPA}" "${NAME}" "${VERSION}")"; then
  echo "Reusing ${orig_name} from ppa:${PPA}."
  curl -fsSL --retry 3 -o "${orig}" "${url}"
  reused_orig=true
else
  tree="${work}/${NAME}-${VERSION}"
  mkdir -p "${tree}"
  git -C "${ROOT}" archive HEAD | tar -x -C "${tree}"
  # Each submodule at the commit HEAD records, whatever its checkout currently holds.
  while read -r _ path; do
    mkdir -p "${tree}/${path}"
    git -C "${ROOT}/${path}" archive "$(git -C "${ROOT}" rev-parse "HEAD:${path}")" | tar -x -C "${tree}/${path}"
  done < <(git -C "${ROOT}" config -f .gitmodules --get-regexp '\.path$' || true)
  tar --sort=name --mtime="@${epoch}" --owner=0 --group=0 --numeric-owner -C "${work}" \
    -cf - "${NAME}-${VERSION}" | xz -T0 -6 > "${orig}"
  rm -rf -- "${tree}"
fi

for series in ${SERIES}; do
  debian_version="${VERSION}-1~${series}${PPA_REVISION}"
  dir="${work}/${series}"
  source_dir="${dir}/${NAME}-${VERSION}"
  mkdir -p "${dir}"
  ln -s "${orig}" "${dir}/${orig_name}"
  tar -xJf "${orig}" -C "${dir}"
  cp -a "${ROOT}/packaging/debian" "${source_dir}/debian"
  chmod 0755 "${source_dir}/debian/rules"
  cat > "${source_dir}/debian/changelog" <<EOF
${NAME} (${debian_version}) ${series}; urgency=medium

  * ${NAME} ${VERSION}.

 -- ${maintainer}  $(date -R -u -d "@${epoch}")
EOF
  # Every upload of a new tarball carries it, since Launchpad may process the series in any order.
  (cd "${source_dir}" && dpkg-buildpackage -S -d -us -uc "$([[ "${reused_orig}" == true ]] && echo -sd || echo -sa)")
  mv "${dir}/${NAME}_${debian_version}"* "${OUTPUT_DIR}/"
  rm -rf -- "${dir}"
done
echo "Unsigned source uploads are in ${OUTPUT_DIR}."
