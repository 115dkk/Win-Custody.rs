//! Process handles with a fixed rights set, and elevation.
#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    DuplicateHandle, DUPLICATE_SAME_ACCESS, ERROR_INSUFFICIENT_BUFFER, FILETIME, STILL_ACTIVE,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, TokenCapabilities, TokenElevation, TokenIsAppContainer,
    SID_AND_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::app_container::DerivedCapability;
use crate::handle::{current_process, owned_from_creation, wait, WaitOutcome};
use crate::launch::command_line_tail;
use crate::wide::wide_null;

const MAX_IMAGE_PATH_UNITS: usize = 32_768;

/// The rights a [`Process`] handle carries.
///
/// Each variant is a fixed rights set. [`Process::open`] cannot request
/// [`ProcessAccess::AsCreated`]: full access is only available on a process
/// this one created, so a reused PID can never be reopened with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProcessAccess {
    /// `PROCESS_QUERY_LIMITED_INFORMATION`: identity and exit-code queries.
    QueryLimited,
    /// `SYNCHRONIZE`: waiting for exit.
    Synchronize,
    /// Identity queries and waiting for exit.
    QueryLimitedAndSynchronize,
    /// Identity queries, waiting for exit, and `PROCESS_TERMINATE`.
    Terminate,
    /// The rights the creating call granted: everything.
    AsCreated,
}

impl ProcessAccess {
    fn rights(self) -> u32 {
        match self {
            Self::QueryLimited => PROCESS_QUERY_LIMITED_INFORMATION,
            Self::Synchronize => SYNCHRONIZE,
            Self::QueryLimitedAndSynchronize => PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            Self::Terminate => PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE,
            Self::AsCreated => 0,
        }
    }
}

/// An open process handle with a fixed rights set.
///
/// The handle names one process object for its whole life, so unlike a PID
/// it cannot start pointing at an unrelated process after the original exits.
#[derive(Debug)]
pub struct Process {
    handle: OwnedHandle,
    access: ProcessAccess,
}

impl Process {
    /// Opens `pid` with exactly `access`. The error carries the Win32 code; a
    /// PID that has left the process table reports `ERROR_INVALID_PARAMETER`.
    pub fn open(pid: u32, access: ProcessAccess) -> io::Result<Self> {
        if access == ProcessAccess::AsCreated {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "full access is only available on a process this one created",
            ));
        }
        // SAFETY: OpenProcess takes plain integers and returns a new handle or
        // null; no memory is shared with the callee.
        let handle = unsafe { OpenProcess(access.rights(), 0, pid) };
        Ok(Self {
            handle: owned_from_creation(handle)?,
            access,
        })
    }

    /// Duplicates the handle `std` holds for `child`. The result keeps every
    /// right `CreateProcess` granted (job assignment and termination among
    /// them, which a reopen by PID would not get).
    pub fn from_child(child: &std::process::Child) -> io::Result<Self> {
        let mut duplicate = ptr::null_mut();
        // SAFETY: the source handle is the live one `child` owns for the
        // duration of this call, both process arguments are the current
        // process pseudo-handle, and `duplicate` is a local out value.
        let duplicated = unsafe {
            DuplicateHandle(
                current_process(),
                child.as_raw_handle(),
                current_process(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if duplicated == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle: owned_from_creation(duplicate)?,
            access: ProcessAccess::AsCreated,
        })
    }

    /// Starts `executable` through the shell's `runas` verb, which shows the
    /// elevation prompt, and returns the process the shell created.
    ///
    /// Each argument is quoted the way `CommandLineToArgvW` parses it, so it
    /// reaches the child unchanged. The child's window starts hidden. A user
    /// who declines the prompt makes this fail with `ERROR_CANCELLED` (1223)
    /// as the Win32 code.
    ///
    /// The shell may need COM: call this from a thread that has initialized
    /// COM if the target is not a plain executable.
    pub fn launch_elevated<I, S>(executable: &Path, arguments: I) -> io::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let arguments: Vec<OsString> = arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_owned())
            .collect();
        let verb = wide_null("runas")?;
        let file = wide_null(executable)?;
        let parameters = command_line_tail(&arguments)?;
        let mut info = SHELLEXECUTEINFOW {
            cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: verb.as_ptr(),
            lpFile: file.as_ptr(),
            lpParameters: parameters.as_ptr(),
            nShow: SW_HIDE,
            ..Default::default()
        };
        // SAFETY: `info` is fully initialised; its string pointers address
        // NUL-terminated buffers that outlive the call, and the shell writes
        // only `hProcess` and `hInstApp` back into it.
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.hProcess.is_null() {
            return Err(io::Error::other(
                "the shell started the target without returning a process handle",
            ));
        }
        Ok(Self {
            handle: owned_from_creation(info.hProcess)?,
            access: ProcessAccess::AsCreated,
        })
    }

    pub(crate) fn from_owned(handle: OwnedHandle, access: ProcessAccess) -> Self {
        Self { handle, access }
    }

    /// The rights this handle carries.
    pub fn access(&self) -> ProcessAccess {
        self.access
    }

    /// The process identifier behind the handle.
    pub fn pid(&self) -> io::Result<u32> {
        // SAFETY: the handle is live; the call takes no pointers.
        let pid = unsafe { GetProcessId(self.raw()) };
        if pid == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pid)
    }

    /// The creation time as a 64-bit `FILETIME` value. Together with the PID it
    /// identifies a process across its whole lifetime, which a PID alone does
    /// not, since Windows reuses PIDs.
    pub fn creation_time(&self) -> io::Result<u64> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: the handle is live and every out pointer refers to a local
        // `FILETIME` that outlives the call.
        let queried = unsafe {
            GetProcessTimes(self.raw(), &mut creation, &mut exit, &mut kernel, &mut user)
        };
        if queried == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
    }

    /// The exit code, or `None` while the process is still running.
    ///
    /// A process may itself exit with code 259 (`STILL_ACTIVE`). When the
    /// handle carries `SYNCHRONIZE`, a zero-length wait tells that case apart
    /// from a running process; without it, 259 is reported as running.
    pub fn exit_code(&self) -> io::Result<Option<u32>> {
        let mut exit_code = 0_u32;
        // SAFETY: the handle is live; the out pointer is a local `u32`.
        if unsafe { GetExitCodeProcess(self.raw(), &mut exit_code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if exit_code == STILL_ACTIVE as u32 {
            match wait(self, Some(Duration::ZERO)) {
                Ok(WaitOutcome::Signaled | WaitOutcome::Abandoned) => {}
                Ok(WaitOutcome::TimedOut) | Err(_) => return Ok(None),
            }
        }
        Ok(Some(exit_code))
    }

    /// Whether this process token is an AppContainer token.
    pub fn is_app_container(&self) -> io::Result<bool> {
        let mut token = ptr::null_mut();
        // SAFETY: `self` owns a live process handle and `token` is a local
        // output pointer. The returned token handle is owned below.
        if unsafe { OpenProcessToken(self.handle.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = owned_from_creation(token)?;
        let mut is_app_container = 0_u32;
        let mut returned = 0_u32;
        // SAFETY: `token` is live and both output pointers name initialized
        // local storage of the documented sizes.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenIsAppContainer,
                (&mut is_app_container as *mut u32).cast(),
                size_of::<u32>() as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if returned as usize != size_of::<u32>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned a truncated AppContainer token flag",
            ));
        }
        Ok(is_app_container != 0)
    }

    /// Whether the process's token holds the Windows capability `name`, such as
    /// `internetClient`.
    ///
    /// The name is turned into SIDs the same way
    /// [`AppContainerProfile::create_or_open_with_capabilities`](crate::AppContainerProfile::create_or_open_with_capabilities)
    /// does. Windows accepts misspelled names, but no token holds the resulting
    /// capability. A process outside an AppContainer holds no capabilities. The
    /// handle needs `PROCESS_QUERY_LIMITED_INFORMATION`, which every
    /// [`ProcessAccess`] variant except [`ProcessAccess::Synchronize`] includes.
    pub fn has_capability(&self, name: &str) -> io::Result<bool> {
        if !self.is_app_container()? {
            return Ok(false);
        }
        let required = DerivedCapability::from_name(name)?;
        let held = token_capability_sids(self)?;
        Ok(required.capability_sids().iter().all(|required_sid| {
            !required_sid.is_null()
                && held.iter().any(|held_sid| {
                    let held_sid = held_sid.as_ptr().cast_mut().cast();
                    // SAFETY: both pointers address complete, live SID
                    // allocations for this comparison.
                    unsafe { EqualSid(*required_sid, held_sid) != 0 }
                })
        }))
    }

    /// The full Win32 path of the process image.
    pub fn image_path(&self) -> io::Result<PathBuf> {
        let mut buffer = vec![0_u16; MAX_IMAGE_PATH_UNITS];
        let mut length = buffer.len() as u32;
        // SAFETY: the handle is live; `buffer` is writable for `length` units,
        // and the API updates `length` with the number of units written.
        let queried = unsafe {
            QueryFullProcessImageNameW(
                self.raw(),
                PROCESS_NAME_WIN32,
                buffer.as_mut_ptr(),
                &mut length,
            )
        };
        if queried == 0 {
            return Err(io::Error::last_os_error());
        }
        if length == 0 || length as usize >= buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process image path length is out of range",
            ));
        }
        buffer.truncate(length as usize);
        Ok(PathBuf::from(OsString::from_wide(&buffer)))
    }

    /// The Terminal Services session the process runs in.
    pub fn session_id(&self) -> io::Result<u32> {
        crate::session::process_session_id(self.pid()?)
    }

    /// Terminates the process with `exit_code`.
    pub fn terminate(&self, exit_code: u32) -> io::Result<()> {
        // SAFETY: the handle is live; the call takes no pointers.
        if unsafe { TerminateProcess(self.raw(), exit_code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Waits for the process to exit. `None` waits forever.
    pub fn wait(&self, timeout: Option<Duration>) -> io::Result<WaitOutcome> {
        wait(self, timeout)
    }

    fn raw(&self) -> RawHandle {
        self.handle.as_raw_handle()
    }
}

pub(crate) fn token_capability_sids(process: &Process) -> io::Result<Vec<Vec<u32>>> {
    let mut raw_token = ptr::null_mut();
    // SAFETY: the process handle is live and `raw_token` is a local output whose
    // returned handle is immediately wrapped as owned.
    if unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = owned_from_creation(raw_token)?;
    let mut needed = 0_u32;
    // SAFETY: this is the documented null-buffer sizing probe and `needed` is a
    // live output pointer.
    let probed = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenCapabilities,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    let probe_error = io::Error::last_os_error();
    if probed != 0 || probe_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(probe_error);
    }
    if needed < size_of::<u32>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TokenCapabilities buffer is shorter than its group count",
        ));
    }
    let words = (needed as usize).div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    let capacity = storage.len() * size_of::<usize>();
    // SAFETY: `storage` is word-aligned and writable for at least `needed`
    // bytes; the token and output length are live for this call.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenCapabilities,
            storage.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if needed as usize > capacity || needed < size_of::<u32>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TokenCapabilities result exceeds its buffer",
        ));
    }
    // SAFETY: the successful call initialized the group count in this aligned
    // buffer, and its returned size includes that field.
    let count = unsafe { *storage.as_ptr().cast::<u32>() as usize };
    if count == 0 {
        return Ok(Vec::new());
    }
    let groups_offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    let groups_bytes = count
        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
        .and_then(|bytes| groups_offset.checked_add(bytes))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "TokenCapabilities group count overflows",
            )
        })?;
    if groups_bytes > needed as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TokenCapabilities group array exceeds its buffer",
        ));
    }
    // SAFETY: `groups_offset` lies within the validated token information
    // buffer, so advancing to the Groups member stays in its allocation.
    let entries_pointer = unsafe { storage.as_ptr().cast::<u8>().add(groups_offset) };
    // SAFETY: the validated byte range contains `count` contiguous entries
    // beginning at `entries_pointer`.
    let entries =
        unsafe { std::slice::from_raw_parts(entries_pointer.cast::<SID_AND_ATTRIBUTES>(), count) };
    // SAFETY: the successful call initialized `needed` bytes in `storage`, and
    // the capacity check above proves that range lies inside the allocation.
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), needed as usize) };
    entries
        .iter()
        .map(|entry| copy_sid_from_token_buffer(entry.Sid, bytes))
        .collect()
}

fn copy_sid_from_token_buffer(sid: *mut std::ffi::c_void, buffer: &[u8]) -> io::Result<Vec<u32>> {
    const SID_FIXED_BYTES: usize = 8;
    let offset = (sid as usize)
        .checked_sub(buffer.as_ptr() as usize)
        .filter(|offset| *offset <= buffer.len().saturating_sub(SID_FIXED_BYTES))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "a token capability SID lies outside the returned buffer",
            )
        })?;
    let sub_authorities = usize::from(buffer[offset + 1]);
    let length = sub_authorities
        .checked_mul(size_of::<u32>())
        .and_then(|bytes| SID_FIXED_BYTES.checked_add(bytes))
        .filter(|length| {
            offset
                .checked_add(*length)
                .is_some_and(|end| end <= buffer.len())
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "a token capability SID exceeds the returned buffer",
            )
        })?;
    let mut copy = vec![0_u32; length.div_ceil(size_of::<u32>())];
    // SAFETY: this mutable byte view covers the initialized u32 allocation and
    // does not outlive `copy`.
    let copy_bytes = unsafe {
        std::slice::from_raw_parts_mut(
            copy.as_mut_ptr().cast::<u8>(),
            copy.len() * size_of::<u32>(),
        )
    };
    copy_bytes[..length].copy_from_slice(&buffer[offset..offset + length]);
    Ok(copy)
}

impl AsHandle for Process {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.handle.as_handle()
    }
}

impl AsRawHandle for Process {
    fn as_raw_handle(&self) -> RawHandle {
        self.raw()
    }
}

impl From<Process> for OwnedHandle {
    fn from(process: Process) -> Self {
        process.handle
    }
}

/// Whether the calling process runs with an elevated (full administrator)
/// token.
pub fn is_elevated() -> io::Result<bool> {
    let mut token = ptr::null_mut();
    // SAFETY: the process pseudo-handle is always valid and `token` is a local
    // out pointer whose handle is owned immediately below.
    if unsafe { OpenProcessToken(current_process(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = owned_from_creation(token)?;
    token_is_elevated(token.as_raw_handle())
}

/// Reads `TokenElevation` from a token opened with `TOKEN_QUERY`.
pub(crate) fn token_is_elevated(token: RawHandle) -> io::Result<bool> {
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0_u32;
    // SAFETY: the caller lends a live token handle; the buffer pointer and
    // length describe exactly the local TOKEN_ELEVATION value.
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    if queried == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(elevation.TokenIsElevated != 0)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;

    use super::{is_elevated, Process, ProcessAccess};
    use crate::handle::WaitOutcome;

    #[test]
    fn the_current_process_opens_and_reports_its_identity() {
        let process = Process::open(std::process::id(), ProcessAccess::QueryLimited).unwrap();
        assert_eq!(process.pid().unwrap(), std::process::id());
        assert_eq!(process.exit_code().unwrap(), None);
        assert!(process.creation_time().unwrap() > 0);
        assert_eq!(
            process.image_path().unwrap(),
            std::env::current_exe().unwrap()
        );
    }

    #[test]
    fn full_access_cannot_be_requested_by_pid() {
        let error = Process::open(std::process::id(), ProcessAccess::AsCreated).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_vanished_pid_reports_invalid_parameter() {
        // PIDs are multiples of four; an odd value is never assigned.
        let error = Process::open(u32::MAX - 2, ProcessAccess::QueryLimited).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(ERROR_INVALID_PARAMETER as i32));
    }

    #[test]
    fn a_std_child_is_adopted_with_its_creation_rights() {
        let mut child = std::process::Command::new("cmd")
            .args(["/d", "/c", "exit 5"])
            .spawn()
            .unwrap();
        let process = Process::from_child(&child).unwrap();
        assert_eq!(process.access(), ProcessAccess::AsCreated);
        assert_eq!(
            process.wait(Some(Duration::from_secs(30))).unwrap(),
            WaitOutcome::Signaled
        );
        assert_eq!(process.exit_code().unwrap(), Some(5));
        child.wait().unwrap();
    }

    #[test]
    fn elevation_is_readable() {
        is_elevated().unwrap();
    }
}
