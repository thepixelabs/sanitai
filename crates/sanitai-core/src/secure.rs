/// Memory safety primitives for secret-bearing data.
///
/// Rules enforced by this module:
/// - `SecureString` and `LockedMemory` do NOT implement `Debug` or `Display`.
/// - All secret-bearing types implement `Zeroize` and `ZeroizeOnDrop`.
/// - `LockedMemory` calls `mlock()` on construction and `zeroize()` before `munlock()` on drop.
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// SecureString
// ---------------------------------------------------------------------------

/// A string that holds secret material. Zeroized on drop.
///
/// Does NOT implement `Debug`, `Display`, or `Clone`. If you need to compare
/// two `SecureString` values, use `ct_eq()` (constant-time).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        Self(s.to_owned())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Constant-time equality check.
    pub fn ct_eq(&self, other: &SecureString) -> bool {
        if self.0.len() != other.0.len() {
            // Still iterate to avoid timing oracle on length.
            let _ = self
                .0
                .bytes()
                .zip(b"x".iter().cycle())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b));
            return false;
        }
        self.0
            .bytes()
            .zip(other.0.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }

    /// Returns a redacted representation safe for logging.
    pub fn redacted(&self) -> String {
        format!("***REDACTED[len={}]***", self.0.len())
    }

    /// Access the raw value. Use only in the detector hot path, never pass to logging.
    /// The name is intentionally verbose to make call sites obvious in code review.
    pub fn expose_secret_for_detection_only(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// LockedMemory
// ---------------------------------------------------------------------------

/// Wraps a value in `mlock`-ed memory. The value is zeroized before `munlock` on drop.
///
/// `mlock` failure is non-fatal (logs a warning) because:
/// - On some systems it requires elevated privileges.
/// - `RLIMIT_MEMLOCK` may be 0.
///   The value is still zeroized on drop even if locking failed.
pub struct LockedMemory<T: Zeroize> {
    inner: Box<T>,
    locked: bool,
}

impl<T: Zeroize> LockedMemory<T> {
    pub fn new(value: T) -> Self {
        let inner = Box::new(value);
        let locked = Self::try_lock(&*inner);
        Self { inner, locked }
    }

    fn try_lock(inner: &T) -> bool {
        #[cfg(unix)]
        {
            let ptr = inner as *const T as *const libc::c_void;
            let size = std::mem::size_of::<T>();
            let rc = unsafe { libc::mlock(ptr, size) };
            if rc != 0 {
                tracing::debug!(
                    "mlock failed (errno {}): secret may be swappable",
                    std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(-1_i32)
                );
                return false;
            }
            true
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> Drop for LockedMemory<T> {
    fn drop(&mut self) {
        // Zeroize BEFORE munlock so the bytes are gone before the pages become swappable.
        self.inner.zeroize();

        if self.locked {
            #[cfg(unix)]
            unsafe {
                let ptr = self.inner.as_ref() as *const T as *const libc::c_void;
                let size = std::mem::size_of::<T>();
                libc::munlock(ptr, size);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Process hardening
// ---------------------------------------------------------------------------

/// Call once at startup, before processing any user input.
///
/// - Disables core dumps (Linux: `prctl(PR_SET_DUMPABLE, 0)`)
/// - Denies ptrace attachment (macOS: `ptrace(PT_DENY_ATTACH, ...)`)
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    unsafe {
        // Prevent core dumps from exposing secret memory.
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }

    #[cfg(target_os = "macos")]
    unsafe {
        // PT_DENY_ATTACH: makes ptrace return EBUSY for this process.
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_string_redacted_does_not_contain_value() {
        let s = SecureString::from_str("sk-ant-super-secret");
        let redacted = s.redacted();
        assert!(!redacted.contains("sk-ant"));
        assert!(redacted.contains("REDACTED"));
    }

    #[test]
    fn secure_string_ct_eq() {
        let a = SecureString::from_str("hello");
        let b = SecureString::from_str("hello");
        let c = SecureString::from_str("world");
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }
}
