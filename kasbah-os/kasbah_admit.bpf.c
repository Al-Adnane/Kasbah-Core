/* kasbah_admit.bpf.c — LSM enforcement sketch for the admission gate.
 *
 * STATUS: SOURCE-COMPLETE, NEVER COMPILED OR LOADED. This Mac has no BPF
 * backend (needs Linux + clang-bpf + kernel 5.7+ with BTF + root). Do not
 * claim enforcement until: (1) builds with `clang -target bpf`, (2) loads
 * on a test VM, (3) the self-test below passes against the loader, (4) an
 * independent reviewer reads the hook list. The userspace policy engine
 * (packages/kernel-ebpf) remains the enforced path everywhere else.
 *
 * Design: two LSM hooks consult pinned maps populated by the admission
 * daemon. Deny decisions emit ring-buffer audit events (audit-then-admit
 * at kernel boundary: the event is emitted BEFORE the denial returns).
 *
 * Build (on Linux):
 *   clang -O2 -target bpf -c kasbah_admit.bpf.c -o kasbah_admit.bpf.o
 *   sudo bpftool prog load kasbah_admit.bpf.o /sys/fs/bpf/kasbah_admit
 *   sudo bpftool map pin ... (see loader notes in packages/kernel-ebpf)
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Deny-listed path prefixes, hashed by userspace loader into this map.
 * Key: u64 fnv1a(path prefix). Value: u8 reason code. Max 64 entries. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u8);
} kasbah_denied_paths SEC(".maps");

/* Quarantined identities (uid or cgroup id -> reason). Max 1024. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} kasbah_quarantine SEC(".maps");

/* Audit ring buffer: every denial emits before returning. 1MB. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} kasbah_audit SEC(".maps");

struct audit_event {
	__u64 hook;      /* 1=file_open 2=socket_connect */
	__u64 id;        /* uid or net tuple hash */
	__u32 pid;
	__u8  decision;  /* 0=allow 1=deny */
	__u8  reason;
	__u16 pad;
};

static __always_inline __u64 fnv1a(const char *s, int n)
{
	__u64 h = 1469598103934665603ULL;
	for (int i = 0; i < n && i < 256; i++) {
		h ^= (__u64)s[i];
		h *= 1099511628211ULL;
	}
	return h;
}

/* LSM hook: file_open. Deny denylisted prefixes + quarantined uids. */
SEC("lsm/file_open")
int BPF_PROG(kasbah_file_open, void *file)
{
	__u64 uid = bpf_get_current_uid_gid() & 0xffffffffULL;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u8 *q = bpf_map_lookup_elem(&kasbah_quarantine, &uid);
	struct audit_event *e;

	if (q) {
		e = bpf_ringbuf_reserve(&kasbah_audit, sizeof(*e), 0);
		if (e) {
			e->hook = 1; e->id = uid; e->pid = pid;
			e->decision = 1; e->reason = *q;
			bpf_ringbuf_submit(e, 0);
		}
		return -13; /* -EACCES */
	}
	/* NOTE: full path walk omitted in this sketch — the loader pins
	 * hashed prefixes; a production hook must walk dentry->d_parent
	 * with bounded loops (verifier limit). See TODO below. */
	return 0;
}

/* LSM hook: socket_connect. Deny cloud-metadata + quarantined uids. */
SEC("lsm/socket_connect")
int BPF_PROG(kasbah_sock_conn, void *sock, void *addr, int addrlen)
{
	__u64 uid = bpf_get_current_uid_gid() & 0xffffffffULL;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u8 *q = bpf_map_lookup_elem(&kasbah_quarantine, &uid);
	struct audit_event *e;

	if (q) {
		e = bpf_ringbuf_reserve(&kasbah_audit, sizeof(*e), 0);
		if (e) {
			e->hook = 2; e->id = uid; e->pid = pid;
			e->decision = 1; e->reason = *q;
			bpf_ringbuf_submit(e, 0);
		}
		return -13;
	}
	return 0;
}

/* TODO before any enforcement claim:
 *  1. dentry path walk with verifier-safe bounded loop.
 *  2. IPv4/IPv6 tuple extraction + metadata-IP constant map.
 *  3. Loader: pin maps, populate from admission daemon, self-test.
 *  4. libbpf skeleton + CO-RE relocations for multi-kernel support.
 */
char LICENSE[] SEC("license") = "GPL";
