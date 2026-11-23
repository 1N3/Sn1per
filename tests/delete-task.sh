#!/bin/bash
# Regression test: `sniper -w <workspace> -t <target> -dt` must remove only the
# named target's running-task markers, and must report how many tasks remain.
#
# Run from the repository root as root (sniper requires EUID 0 and installs to
# /usr/share/sniper):
#
#   bash tests/delete-task.sh
#
# Uses a throwaway workspace named `-dt-regression` and performs no network I/O.

set -u

INSTALL_DIR=/usr/share/sniper
WORKSPACE="-dt-regression"
LOOT_DIR="$INSTALL_DIR/loot/workspace/$WORKSPACE"

if [[ $EUID -ne 0 ]]; then
  echo "This test must be run as root (sniper itself requires root)."
  exit 1
fi

fail=0
check() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "PASS: $desc"
  else
    echo "FAIL: $desc (expected '$expected', got '$actual')"
    fail=1
  fi
}

# Seed two independent scans in one workspace.
rm -rf "$LOOT_DIR"
mkdir -p "$LOOT_DIR/scans"
echo "sniper -t hostA -m stealth --noreport" > "$LOOT_DIR/scans/running_hostA_stealth.txt"
echo "sniper -t hostB -m stealth --noreport" > "$LOOT_DIR/scans/running_hostB_stealth.txt"
echo "2" > "$LOOT_DIR/scans/tasks-running.txt"

# Delete only hostA's tasks.
sniper -w "$WORKSPACE" -t hostA -dt > /dev/null 2>&1

check "hostA task markers removed" "" \
      "$(ls -1 "$LOOT_DIR/scans" 2>/dev/null | grep '^running_hostA' | tr '\n' ' ')"
check "hostB task markers untouched" "running_hostB_stealth.txt " \
      "$(ls -1 "$LOOT_DIR/scans" 2>/dev/null | grep '^running_hostB' | tr '\n' ' ')"
check "remaining task count reported" "1" \
      "$(cat "$LOOT_DIR/scans/tasks-running.txt" 2>/dev/null)"

rm -rf "$LOOT_DIR"

if [[ $fail -eq 0 ]]; then
  echo "All -dt regression checks passed."
fi
exit $fail
