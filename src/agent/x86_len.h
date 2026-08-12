/* SPDX-License-Identifier: GPL-2.0 */
/* Minimal x86-64 instruction-length decoder, and the one thing latkit needs it
 * for: finding the return sites of a function (РH13.3, PLAN-HTTP.md М7).
 *
 * Why an agent contains a disassembler at all. The Go plaintext channel cannot
 * use a uretprobe: the kernel implements one by overwriting the return address
 * on the stack, and the Go runtime copies goroutine stacks when they grow — the
 * saved trampoline address moves with the copy and the probe is lost, or worse,
 * a stale one is hit. The way out (the same one Pixie and eCapture take) is to
 * put ordinary uprobes on the `ret` instructions inside the function body. To
 * find them you cannot search for the byte 0xC3: it appears constantly inside
 * immediates, displacements and ModRM bytes. You have to walk the instruction
 * stream from a known boundary — the function's first byte — and only a decoder
 * gives you that.
 *
 * The contract this module holds itself to is **fail closed**. A uprobe placed
 * in the middle of an instruction corrupts the observed process, which is the
 * one outcome an observability agent must never produce. So every opcode the
 * table does not positively recognise, every prefix combination outside the
 * subset a Go compiler emits (VEX/EVEX included), and every walk that does not
 * land exactly on the function's last byte is reported as failure — and the
 * caller then leaves that function unhooked and says so. Refusing to attach is
 * a blind zone; guessing is a crash.
 *
 * Pure: no allocation, no I/O, no libbpf. Table-driven and table-tested
 * (tests/unit/test_x86_len.c). */
#ifndef LATKIT_X86_LEN_H
#define LATKIT_X86_LEN_H

#include <stddef.h>
#include <stdint.h>

/* Length in bytes of the instruction at p, with n bytes readable there.
 * Returns 1..15 on success, -1 when the instruction is not in the supported
 * subset or would run past p+n (a truncated tail is a failure, not a guess). */
int lk_x86_insn_len(const uint8_t *p, size_t n);

/* Offsets of every near-return (`ret`, 0xC3) in the function body [code,
 * code+len), decoded from the first byte. The offset is that of the
 * instruction's first byte — its prefixes included, if any — which is where a
 * uprobe belongs.
 *
 * Returns the number of returns written to out[0..max), or -1 if the body does
 * not decode cleanly end to end: an unsupported opcode, or a last instruction
 * that does not finish exactly at code+len (the sign that the walk lost the
 * boundary somewhere behind it). More than `max` returns is also a failure —
 * silently hooking some of the exits would make the miss look like a
 * correlation problem instead of a configuration one. */
int lk_x86_find_rets(const uint8_t *code, size_t len, uint32_t *out, int max);

#endif /* LATKIT_X86_LEN_H */
