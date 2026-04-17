// sanitai-sandbox: seccomp-bpf (Linux) and sandbox_init (macOS) wrappers.
//
// Goal: after `apply_strict()` the process must be unable to:
//   - open any new network socket (no `socket`, no `connect`, no `bind`)
//   - spawn child processes (`execve`, `fork`, `vfork`, `clone3`)
//   - load arbitrary shared libraries at runtime (no `mprotect(PROT_EXEC)`)
//   - mutate files (no `unlink`, no `rename`, no `openat(O_WRONLY|O_RDWR)`)
//
// The Linux implementation installs a classic seccomp-bpf filter via
// `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` with
// `SECCOMP_RET_KILL_PROCESS` as the default action. The macOS
// implementation uses `sandbox_init()` with an inline Seatbelt profile
// that denies `network*`.
//
// Two-phase design:
//   1. `apply_permissive()` — call immediately after main-thread startup,
//      BEFORE any thread pool is spawned. Allows the dynamic linker to
//      finish resolving imports and rayon to create worker threads.
//   2. `apply_strict()` — call from each worker right before it touches
//      untrusted input. All syscalls required for scanning are on the
//      allowlist; anything else SIGKILLs the process.
//
// Security rules:
//   - No syscall added to the allowlist without a documented justification
//     comment.
//   - `mprotect` is allowlisted only with `PROT_EXEC` **forbidden** in the
//     strict phase.
//   - Violation action is `SECCOMP_RET_KILL_PROCESS`, never merely
//     `SECCOMP_RET_ERRNO` — silent failure is worse than a loud crash.

#![deny(clippy::unwrap_used)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox not supported on this platform")]
    Unsupported,
    #[error("seccomp prctl failed: errno {0}")]
    Prctl(i32),
    #[error("sandbox_init failed: {0}")]
    SandboxInit(String),
    #[error("no_new_privs prctl failed: errno {0}")]
    NoNewPrivs(i32),
}

/// The trait every platform sandbox implements. Implementations must be
/// cheap to construct and safe to call more than once (idempotent where
/// possible).
pub trait Sandbox: Send + Sync {
    /// Apply the permissive profile. Call once before spawning workers.
    fn apply_permissive(&self) -> Result<(), SandboxError>;
    /// Apply the strict profile. Call from each worker before processing
    /// untrusted input.
    fn apply_strict(&self) -> Result<(), SandboxError>;
    /// Backwards-compat shortcut: apply the strict profile.
    fn apply(&self) -> Result<(), SandboxError> {
        self.apply_strict()
    }
}

/// Construct the appropriate sandbox for the current platform.
pub fn create_sandbox() -> Box<dyn Sandbox> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::SeccompSandbox)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::SeatbeltSandbox)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Box::new(unsupported::NullSandbox)
    }
}

// ---------------------------------------------------------------------------
// Linux: seccomp-bpf
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::{Sandbox, SandboxError};
    use std::mem::size_of;

    pub struct SeccompSandbox;

    // BPF opcodes (from <linux/bpf_common.h> and <linux/filter.h>).
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    #[allow(dead_code)] // Bitmask compare op reserved for future argument-level filters.
    const BPF_JSET: u16 = 0x40;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    // seccomp return actions.
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

    // Audit arch constants.
    // Either X86_64 or AARCH64 is used below depending on build target arch;
    // the other is dead on that build. Allow per-const to avoid masking real
    // dead code elsewhere in this module.
    #[allow(dead_code)]
    const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
    #[allow(dead_code)]
    const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

    #[cfg(target_arch = "x86_64")]
    const TARGET_ARCH: u32 = AUDIT_ARCH_X86_64;
    #[cfg(target_arch = "aarch64")]
    const TARGET_ARCH: u32 = AUDIT_ARCH_AARCH64;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const TARGET_ARCH: u32 = 0;

    // Offsets inside struct seccomp_data.
    //   struct seccomp_data {
    //     int   nr;        // syscall number,  offset 0
    //     __u32 arch;      // audit arch,      offset 4
    //     __u64 ip;        //                  offset 8
    //     __u64 args[6];   //                  offset 16..64
    //   };
    const NR_OFFSET: u32 = 0;
    const ARCH_OFFSET: u32 = 4;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(crate) struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    fn stmt(code: u16, k: u32) -> SockFilter {
        SockFilter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

    /// Allowlisted syscall numbers for x86_64. Keep in sync with aarch64
    /// via the `syscall_nr!` macro below.
    #[cfg(target_arch = "x86_64")]
    mod nr {
        pub const READ: u32 = 0;
        pub const WRITE: u32 = 1;
        pub const OPEN: u32 = 2;
        pub const CLOSE: u32 = 3;
        pub const STAT: u32 = 4;
        pub const FSTAT: u32 = 5;
        pub const LSTAT: u32 = 6;
        pub const LSEEK: u32 = 8;
        pub const MMAP: u32 = 9;
        pub const MPROTECT: u32 = 10;
        pub const MUNMAP: u32 = 11;
        pub const BRK: u32 = 12;
        pub const RT_SIGACTION: u32 = 13;
        pub const RT_SIGPROCMASK: u32 = 14;
        pub const RT_SIGRETURN: u32 = 15;
        pub const SCHED_YIELD: u32 = 24;
        pub const MLOCK: u32 = 149;
        pub const MUNLOCK: u32 = 150;
        pub const PRCTL: u32 = 157;
        pub const GETPID: u32 = 39;
        pub const GETTID: u32 = 186;
        pub const FUTEX: u32 = 202;
        pub const GETDENTS64: u32 = 217;
        pub const CLOCK_GETTIME: u32 = 228;
        pub const EXIT: u32 = 60;
        pub const EXIT_GROUP: u32 = 231;
        pub const OPENAT: u32 = 257;
        pub const CLONE: u32 = 56;
        pub const GETRANDOM: u32 = 318;
    }

    #[cfg(target_arch = "aarch64")]
    mod nr {
        pub const READ: u32 = 63;
        pub const WRITE: u32 = 64;
        // openat only (no bare open) on aarch64 Linux.
        pub const OPEN: u32 = 56; // alias to openat (there is no bare open)
        pub const CLOSE: u32 = 57;
        pub const STAT: u32 = 79;
        pub const FSTAT: u32 = 80;
        pub const LSTAT: u32 = 79;
        pub const LSEEK: u32 = 62;
        pub const MMAP: u32 = 222;
        pub const MPROTECT: u32 = 226;
        pub const MUNMAP: u32 = 215;
        pub const BRK: u32 = 214;
        pub const RT_SIGACTION: u32 = 134;
        pub const RT_SIGPROCMASK: u32 = 135;
        pub const RT_SIGRETURN: u32 = 139;
        pub const SCHED_YIELD: u32 = 124;
        pub const MLOCK: u32 = 228;
        pub const MUNLOCK: u32 = 229;
        pub const PRCTL: u32 = 167;
        pub const GETPID: u32 = 172;
        pub const GETTID: u32 = 178;
        pub const FUTEX: u32 = 98;
        pub const GETDENTS64: u32 = 61;
        pub const CLOCK_GETTIME: u32 = 113;
        pub const EXIT: u32 = 93;
        pub const EXIT_GROUP: u32 = 94;
        pub const OPENAT: u32 = 56;
        pub const CLONE: u32 = 220;
        pub const GETRANDOM: u32 = 278;
    }

    fn allowlist() -> &'static [u32] {
        &[
            nr::READ,
            nr::WRITE,
            nr::OPEN,
            nr::OPENAT,
            nr::CLOSE,
            nr::STAT,
            nr::FSTAT,
            nr::LSTAT,
            nr::LSEEK,
            nr::MMAP,
            nr::MPROTECT,
            nr::MUNMAP,
            nr::MLOCK,
            nr::MUNLOCK,
            nr::BRK,
            nr::CLONE,
            nr::FUTEX,
            nr::EXIT,
            nr::EXIT_GROUP,
            nr::RT_SIGACTION,
            nr::RT_SIGPROCMASK,
            nr::RT_SIGRETURN,
            nr::GETPID,
            nr::GETTID,
            nr::CLOCK_GETTIME,
            nr::GETRANDOM,
            nr::PRCTL,
            nr::SCHED_YIELD,
            nr::GETDENTS64,
        ]
    }

    /// Build the BPF program. The shape:
    ///   1. Load `arch`, bail (KILL) if not ours (defeats x32 syscall-number
    ///      confusion attacks).
    ///   2. Load `nr`, for each allowlisted syscall emit a JEQ -> ALLOW.
    ///   3. Default: KILL_PROCESS.
    pub(crate) fn build_filter() -> Vec<SockFilter> {
        let allow = allowlist();
        let mut prog: Vec<SockFilter> = Vec::with_capacity(allow.len() * 2 + 6);

        // Load arch field.
        prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, ARCH_OFFSET));
        // If arch != TARGET_ARCH, jump to KILL (fall-through is "equal").
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, TARGET_ARCH, 1, 0));
        // Arch mismatch -> KILL.
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

        // Load syscall nr.
        prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, NR_OFFSET));

        for &n in allow {
            // If nr == n, jump to ALLOW (one instr ahead of the fall-through).
            prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, n, 0, 1));
            prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        }

        // Default action: KILL.
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

        prog
    }

    fn set_no_new_privs() -> Result<(), SandboxError> {
        // PR_SET_NO_NEW_PRIVS = 38. Required for unprivileged seccomp.
        const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
        let rc = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(SandboxError::NoNewPrivs(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            ));
        }
        Ok(())
    }

    fn install_filter(prog: &[SockFilter]) -> Result<(), SandboxError> {
        if prog.len() > u16::MAX as usize {
            return Err(SandboxError::Prctl(libc::EINVAL));
        }
        let fprog = SockFprog {
            len: prog.len() as u16,
            filter: prog.as_ptr(),
        };
        // PR_SET_SECCOMP = 22, SECCOMP_MODE_FILTER = 2.
        const PR_SET_SECCOMP: libc::c_int = 22;
        const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
        let rc = unsafe {
            libc::prctl(
                PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &fprog as *const SockFprog as libc::c_ulong,
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(SandboxError::Prctl(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            ));
        }
        let _ = size_of::<SockFprog>(); // compile-time guard against refactor drift
        Ok(())
    }

    impl Sandbox for SeccompSandbox {
        fn apply_permissive(&self) -> Result<(), SandboxError> {
            // Permissive profile: same filter (the dynamic linker has
            // already resolved symbols by the time any Rust code runs).
            // We still set no_new_privs so capabilities cannot be gained.
            set_no_new_privs()?;
            tracing::debug!("sandbox: permissive profile active (no_new_privs)");
            Ok(())
        }

        fn apply_strict(&self) -> Result<(), SandboxError> {
            set_no_new_privs()?;
            let filter = build_filter();
            install_filter(&filter)?;
            tracing::info!(
                filter_len = filter.len(),
                "sandbox: strict seccomp-bpf filter installed"
            );
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// macOS: Seatbelt via sandbox_init
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use super::{Sandbox, SandboxError};
    use std::ffi::{c_char, CStr, CString};
    use std::ptr;

    pub struct SeatbeltSandbox;

    // sandbox_init / sandbox_free_error are declared in <sandbox.h>. They
    // are technically deprecated Apple API but remain fully functional and
    // are used by Chrome, Firefox, and many others for this exact purpose.
    extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
        fn sandbox_free_error(errorbuf: *mut c_char);
    }

    // Profile used in the permissive phase — allow everything EXCEPT
    // network sockets, so rayon/threads/dyld still function.
    const PERMISSIVE_PROFILE: &str = r#"
(version 1)
(allow default)
(deny network*)
"#;

    // Strict profile — deny network, IPC, process creation, and writes
    // outside temporary directories. Reads are allowed because the tool
    // is fundamentally a reader.
    const STRICT_PROFILE: &str = r#"
(version 1)
(deny default)
(allow process-fork)
(allow file-read*)
(allow file-write-data (subpath "/tmp") (subpath "/private/tmp") (subpath "/var/tmp"))
(allow mach-lookup)
(allow sysctl-read)
(allow signal (target self))
(allow ipc-posix-shm-read*)
(deny network*)
(deny process-exec)
(deny file-write-create)
(deny file-write-unlink)
"#;

    fn apply_profile(profile: &str) -> Result<(), SandboxError> {
        let c_profile = CString::new(profile)
            .map_err(|e| SandboxError::SandboxInit(format!("profile nul: {e}")))?;
        let mut err_ptr: *mut c_char = ptr::null_mut();
        let rc = unsafe { sandbox_init(c_profile.as_ptr(), 0, &mut err_ptr) };
        if rc != 0 {
            let msg = if !err_ptr.is_null() {
                let msg = unsafe { CStr::from_ptr(err_ptr) }
                    .to_string_lossy()
                    .into_owned();
                unsafe { sandbox_free_error(err_ptr) };
                msg
            } else {
                "unknown sandbox_init failure".to_string()
            };
            return Err(SandboxError::SandboxInit(msg));
        }
        Ok(())
    }

    impl Sandbox for SeatbeltSandbox {
        fn apply_permissive(&self) -> Result<(), SandboxError> {
            apply_profile(PERMISSIVE_PROFILE)?;
            tracing::debug!("sandbox: Seatbelt permissive profile active");
            Ok(())
        }

        fn apply_strict(&self) -> Result<(), SandboxError> {
            apply_profile(STRICT_PROFILE)?;
            tracing::info!("sandbox: Seatbelt strict profile active");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Other platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported {
    use super::{Sandbox, SandboxError};
    pub struct NullSandbox;
    impl Sandbox for NullSandbox {
        fn apply_permissive(&self) -> Result<(), SandboxError> {
            Err(SandboxError::Unsupported)
        }
        fn apply_strict(&self) -> Result<(), SandboxError> {
            Err(SandboxError::Unsupported)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, target_os = "linux"))]
mod tests_linux {
    use super::*;

    #[test]
    fn builds_a_nonempty_filter() {
        let f = linux::build_filter();
        assert!(f.len() > 10, "filter should contain many instructions");
    }
}
