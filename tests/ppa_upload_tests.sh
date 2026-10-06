#!/usr/bin/env bash
set -euo pipefail

source_dir="$(cd "${1:?source directory is required}" && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf -- "${temporary}"' EXIT
mkdir "${temporary}/bin"

cat > "${temporary}/bin/mock" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
command_name="${0##*/}"
printf '%s %s\n' "${command_name}" "$*" >> "${MOCK_STATE}/commands"
case "${command_name}" in
  gpg)
    if [[ "$*" == *--list-secret-keys* ]]; then
      printf 'fpr:::::::::test-fingerprint:\n'
    else
      cat >/dev/null
    fi
    ;;
  python3)
    [[ "$#" -eq 5 && "$2" == has-version ]]
    series="${5##*~}"
    [[ -f "${MOCK_STATE}/${series}.published" ]]
    ;;
  debsign)
    printf 'Mock-Signature: signed\n' >> "${!#}"
    ;;
  dput)
    changes="${!#}"
    series="${changes##*/}"
    series="${series%.changes}"
    grep -q '^Mock-Signature: signed$' "${changes}"
    printf '%s %s\n' "${series}" "$(sha256sum "${changes}" | cut -d ' ' -f 1)" \
      >> "${MOCK_STATE}/payloads"
    attempts=$(($(cat "${MOCK_STATE}/${series}.attempts") + 1))
    printf '%s\n' "${attempts}" > "${MOCK_STATE}/${series}.attempts"
    if [[ "$(cat "${MOCK_STATE}/${series}.accept")" == true ]]; then
      touch "${MOCK_STATE}/${series}.published"
    fi
    if [[ "${attempts}" -le "$(cat "${MOCK_STATE}/${series}.failures")" ]]; then
      exit 7
    fi
    ;;
  gpgconf|sleep) ;;
  *) exit 99 ;;
esac
EOF
chmod 0755 "${temporary}/bin/mock"
for command_name in gpg gpgconf python3 debsign dput sleep; do
  ln -s mock "${temporary}/bin/${command_name}"
done

prepare_case() {
  local state="${temporary}/$1" series
  mkdir "${state}"
  : > "${state}/commands"
  : > "${state}/payloads"
  for series in series-one series-two; do
    printf '0\n' > "${state}/${series}.attempts"
    printf '0\n' > "${state}/${series}.failures"
    printf 'false\n' > "${state}/${series}.accept"
    printf 'Source: test-package\nVersion: 1.0.0-1~%s\n' "${series}" \
      > "${state}/${series}.changes"
  done
}

run_case() {
  local name="$1" expected_status="$2" first_attempts="$3" second_attempts="$4" expected_delays="$5"
  local state="${temporary}/${name}" status=0 series expected_attempts expected_signs hashes
  PPA_GPG_PRIVATE_KEY=test-key PATH="${temporary}/bin:${PATH}" MOCK_STATE="${state}" \
    bash "${source_dir}/packaging/ppa/upload.sh" owner/ppa \
    "${state}/series-one.changes" "${state}/series-two.changes" \
    > "${state}/output" 2>&1 || status=$?
  [[ "${status}" -eq "${expected_status}" ]]
  for series in series-one series-two; do
    expected_attempts="${first_attempts}"
    [[ "${series}" == series-one ]] || expected_attempts="${second_attempts}"
    [[ "$(cat "${state}/${series}.attempts")" -eq "${expected_attempts}" ]]
    expected_signs=0
    if [[ "${expected_attempts}" -gt 0 ]]; then
      expected_signs=1
      hashes="$(awk -v series="${series}" '$1 == series { print $2 }' "${state}/payloads" | sort -u | wc -l)"
      [[ "${hashes}" -eq 1 ]]
    fi
    [[ "$(grep -c "^debsign .*${series}\.changes$" "${state}/commands" || true)" -eq "${expected_signs}" ]]
  done
  [[ "$(sed -n 's/^sleep //p' "${state}/commands" | paste -sd ',' -)" == "${expected_delays}" ]]
  if [[ "${expected_status}" -ne 0 ]]; then
    grep -q 'failed after 3 attempts' "${state}/output"
    grep -q 'series-one.changes' "${state}/output"
  fi
  echo "${name} passed"
}

prepare_case already-published
touch "${temporary}/already-published/series-one.published"
run_case already-published 0 0 1 ''

prepare_case first-success
run_case first-success 0 1 1 ''

prepare_case transient-failure
printf '2\n' > "${temporary}/transient-failure/series-one.failures"
run_case transient-failure 0 3 1 '10,20'

prepare_case permanent-failure
printf '3\n' > "${temporary}/permanent-failure/series-one.failures"
run_case permanent-failure 7 3 0 '10,20'

prepare_case accepted-after-failure
printf '3\n' > "${temporary}/accepted-after-failure/series-one.failures"
printf 'true\n' > "${temporary}/accepted-after-failure/series-one.accept"
run_case accepted-after-failure 0 1 1 ''

prepare_case later-series-retry
printf '2\n' > "${temporary}/later-series-retry/series-two.failures"
run_case later-series-retry 0 1 3 '10,20'
