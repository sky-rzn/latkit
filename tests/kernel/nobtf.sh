#!/usr/bin/env bash
#
# No-BTF negative test (task 8.4, Р52). Every latkit program is CO-RE and
# relocates against the running kernel's BTF, so a kernel built without
# CONFIG_DEBUG_INFO_BTF cannot work — the floor is "5.15+ WITH BTF". This test
# proves the agent then fails with one clear line and a clean exit, never a
# segfault and never running "blind" (silent zeros).
#
# It reproduces the runtime signal of a no-BTF kernel rather than booting one:
# in a private mount namespace it overmounts /sys/kernel/btf with an empty
# tmpfs, so /sys/kernel/btf/vmlinux vanishes — exactly what the agent's startup
# check and libbpf's CO-RE loader both key off. That is faithful (the agent
# cannot tell an overmounted BTF dir from a kernel that never had one) and
# costs no 20-minute from-source kernel build; the matrix already boots real
# 5.15/6.1/6.8/stable kernels for the positive path (smoke.sh). Needs root for
# the mount namespace — the same privilege the agent itself needs.
set -u

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BUILD=${BUILD_DIR:-$REPO_ROOT/build}
AGENT=$BUILD/latkit

# Re-exec into a fresh mount namespace where the overmount is private.
if [ "${LK_NOBTF_REEXEC:-}" != 1 ]; then
    exec env LK_NOBTF_REEXEC=1 unshare -m "$0" "$@"
fi

if [ ! -x "$AGENT" ]; then
    echo "  FAIL - agent binary not found: $AGENT (build first)"
    exit 1
fi

# Make the overmount invisible to the rest of the host, then hide BTF.
mount --make-rprivate / 2>/dev/null || true
if ! mount -t tmpfs none /sys/kernel/btf; then
    echo "  FAIL - could not overmount /sys/kernel/btf (need root / CAP_SYS_ADMIN)"
    exit 1
fi
if [ -e /sys/kernel/btf/vmlinux ]; then
    echo "  FAIL - /sys/kernel/btf/vmlinux still present after overmount"
    exit 1
fi

echo "=== no-BTF negative test ($(uname -r)) ==="
out=$("$AGENT" -p 5499 --prom-listen none 2>&1)
rc=$?
printf '  agent said: %s\n' "$out"
printf '  agent exit: %s\n' "$rc"

fails=0
# Clean refusal, not a crash: SIGSEGV/SIGABRT would surface as 139/134.
if [ "$rc" -eq 0 ]; then
    echo "  FAIL - agent exited 0 without BTF (ran blind?)"
    fails=$((fails + 1))
elif [ "$rc" -ge 128 ]; then
    echo "  FAIL - agent died on signal $((rc - 128)) (segfault, not a diagnostic)"
    fails=$((fails + 1))
else
    echo "  ok   - agent refused with a non-zero exit ($rc), no crash"
fi
if printf '%s' "$out" | grep -qi 'BTF'; then
    echo "  ok   - message names BTF as the missing requirement"
else
    echo "  FAIL - message does not mention BTF: $out"
    fails=$((fails + 1))
fi

if [ "$fails" -eq 0 ]; then
    echo "  no-BTF: passed"
    exit 0
fi
echo "  no-BTF: $fails check(s) failed"
exit 1
