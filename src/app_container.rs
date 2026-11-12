//! AppContainer profiles and the process-creation capability attribute.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{LocalFree, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Globalization::lstrlenW;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
    EXPLICIT_ACCESS_W, SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_GROUP, TRUSTEE_IS_SID, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    DeriveCapabilitySidsFromName, FreeSid, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
    OBJECT_INHERIT_ACE, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;

use crate::wide::wide_null;

const PROFILE_ALREADY_EXISTS: u32 = 0x8007_00b7;

/// A named AppContainer profile and the capabilities assigned to its child
/// processes. Profile data persists in Windows after this value is dropped.
///
/// A process launched in the profile still has everything Windows grants to
/// ALL APPLICATION PACKAGES (`S-1-15-2-1`): read and execute access to the
/// Windows and Program Files directories, and to every registry key that
/// grants that SID access. This is a plain AppContainer, not a Less
/// Privileged AppContainer (LPAC).
pub struct AppContainerProfile {
    sid: AppContainerSid,
    _capabilities: Vec<DerivedCapability>,
    capability_attributes: Vec<SID_AND_ATTRIBUTES>,
    name: Vec<u16>,
    created: bool,
}

// SAFETY: the profile owns every SID and SID pointer array reachable through
// its fields. They are written once during construction and only read after
// construction, with no interior mutability, and the Windows readers have no
// thread affinity, so ownership may move between threads.
unsafe impl Send for AppContainerProfile {}
// SAFETY: every owned SID and SID pointer array is immutable after
// construction, there is no interior mutability, and Windows only reads these
// allocations through APIs with no thread affinity, so shared access is safe.
unsafe impl Sync for AppContainerProfile {}

impl AppContainerProfile {
    /// Creates or opens a named AppContainer profile with no capabilities.
    ///
    /// With no capabilities, the profile receives no optional network or
    /// device access. The name must be unique to the application and at most
    /// 64 UTF-16 code units, as required by Windows. Use
    /// [`was_created`](Self::was_created) to distinguish a newly created
    /// profile from an existing one.
    pub fn create_or_open(name: &str, display_name: &str, description: &str) -> io::Result<Self> {
        Self::create_or_open_with_capabilities(name, display_name, description, &[])
    }

    /// Creates or opens a named AppContainer profile and grants the named
    /// Windows capabilities to processes launched in it.
    ///
    /// Windows does not validate capability names:
    /// `DeriveCapabilitySidsFromName` turns any non-empty string into a SID,
    /// so a misspelled name succeeds and the child runs without the
    /// capability that was meant. Use the names Microsoft documents, such as
    /// `internetClient`. An empty name is rejected.
    pub fn create_or_open_with_capabilities(
        name: &str,
        display_name: &str,
        description: &str,
        capabilities: &[&str],
    ) -> io::Result<Self> {
        let name_w = wide_null(name)?;
        if name_w.len() > 65 || name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AppContainer profile names must be 1 to 64 UTF-16 code units",
            ));
        }
        let display_w = wide_null(display_name)?;
        let description_w = wide_null(description)?;
        let mut derivations = Vec::with_capacity(capabilities.len());
        for capability in capabilities {
            derivations.push(DerivedCapability::from_name(capability)?);
        }
        let mut capability_attributes = Vec::new();
        for derivation in &derivations {
            capability_attributes.extend(derivation.capability_sids.iter().map(|sid| {
                SID_AND_ATTRIBUTES {
                    Sid: *sid,
                    Attributes: SE_GROUP_ENABLED as u32,
                }
            }));
        }

        let mut sid = ptr::null_mut();
        // SAFETY: all UTF-16 strings and capability attributes remain live
        // across the call; `sid` is a local out pointer. Windows returns the
        // profile SID allocation owned by `AppContainerSid`.
        let result = unsafe {
            CreateAppContainerProfile(
                name_w.as_ptr(),
                display_w.as_ptr(),
                description_w.as_ptr(),
                if capability_attributes.is_empty() {
                    ptr::null()
                } else {
                    capability_attributes.as_ptr()
                },
                capability_attributes.len() as u32,
                &mut sid,
            )
        };
        let created = if result as u32 == PROFILE_ALREADY_EXISTS {
            // SAFETY: the profile name is valid and NUL-terminated; `sid` is
            // a local out pointer whose allocation is freed with FreeSid.
            let derived =
                unsafe { DeriveAppContainerSidFromAppContainerName(name_w.as_ptr(), &mut sid) };
            if derived < 0 {
                return Err(hresult_error(derived));
            }
            false
        } else if result < 0 {
            return Err(hresult_error(result));
        } else {
            true
        };
        if sid.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned a null AppContainer SID",
            ));
        }
        Ok(Self {
            sid: AppContainerSid(sid),
            _capabilities: derivations,
            capability_attributes,
            name: name_w,
            created,
        })
    }

    /// Whether this call created the profile.
    ///
    /// `false` means a profile with this name already existed and was opened.
    /// An existing profile may belong to another program or to an earlier
    /// version of yours, and it keeps every access rule ever granted to its SID.
    pub fn was_created(&self) -> bool {
        self.created
    }

    /// Deletes the profile from Windows: its registry data and its folder
    /// under `%LOCALAPPDATA%\Packages`.
    ///
    /// Access granted with [`grant_path`](Self::grant_path) is not removed,
    /// because those rules live on the files themselves and name the
    /// profile's SID. A process already running in the container keeps
    /// running.
    pub fn delete(self) -> io::Result<()> {
        // SAFETY: `self.name` is the NUL-terminated profile name retained from
        // construction and remains live through the call.
        let result = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
        if result < 0 {
            return Err(hresult_error(result));
        }
        Ok(())
    }

    /// The profile's SID in standard string form, for security descriptors on
    /// files, directories, and named pipes.
    ///
    /// A named-pipe descriptor must also allow the user and carry the low
    /// mandatory label `S:(ML;;NW;;;LW)`, because an AppContainer runs at low
    /// integrity.
    pub fn sid_string(&self) -> io::Result<String> {
        let mut string = ptr::null_mut();
        // SAFETY: `self.sid` is a live SID and `string` is a local out
        // pointer. The returned string allocation is freed below.
        if unsafe { ConvertSidToStringSidW(self.sid.0, &mut string) } == 0 || string.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: ConvertSidToStringSidW returns a readable NUL-terminated
        // string that remains live until the matching LocalFree below.
        let length = unsafe { lstrlenW(string) };
        if length < 0 {
            // SAFETY: the allocation came from ConvertSidToStringSidW.
            unsafe { LocalFree(string.cast()) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned an invalid SID string",
            ));
        }
        // SAFETY: `length` was measured through the terminating NUL.
        let value =
            unsafe { OsString::from_wide(std::slice::from_raw_parts(string, length as usize)) };
        // SAFETY: the allocation came from ConvertSidToStringSidW.
        unsafe { LocalFree(string.cast()) };
        value
            .into_string()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SID string was not Unicode"))
    }

    /// Adds an inheritable access rule for this profile to an existing file or
    /// directory DACL without replacing its other access rules.
    ///
    /// Windows propagates inheritable rules to existing descendants when the
    /// DACL is set, so on a directory this rewrites the ACL of every file and
    /// folder under it, which can take a while on a large tree. Files created
    /// later inherit the rule too.
    ///
    /// The grant is persistent: it stays after this value is dropped, after
    /// the launched processes exit and after the profile is deleted, and this
    /// crate has no call to remove it. [`AppContainerAccess::ReadWrite`] also
    /// grants delete access, so a child can replace files inside a writable
    /// directory.
    pub fn grant_path(&self, path: impl AsRef<Path>, access: AppContainerAccess) -> io::Result<()> {
        grant_sid_access(path.as_ref(), self.sid.0, access)
    }

    pub(crate) fn security_capabilities(&self) -> SECURITY_CAPABILITIES {
        SECURITY_CAPABILITIES {
            AppContainerSid: self.sid.0,
            Capabilities: if self.capability_attributes.is_empty() {
                ptr::null_mut()
            } else {
                self.capability_attributes.as_ptr().cast_mut()
            },
            CapabilityCount: self.capability_attributes.len() as u32,
            Reserved: 0,
        }
    }
}

/// Filesystem rights granted by [`AppContainerProfile::grant_path`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AppContainerAccess {
    /// Lists directories and reads files and attributes, without execute access.
    Read,
    /// Reads, writes, and deletes files, without execute access.
    ReadWrite,
}

fn grant_sid_access(path: &Path, sid: PSID, access: AppContainerAccess) -> io::Result<()> {
    let path = wide_null(path.as_os_str())?;
    let mut old_dacl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: `path` is NUL-terminated and both outputs are local pointers;
    // Windows returns a LocalAlloc descriptor owned by the guard below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut old_dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = LocalBlock(descriptor.cast());
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: match access {
            AppContainerAccess::Read => GENERIC_READ,
            AppContainerAccess::ReadWrite => GENERIC_READ | GENERIC_WRITE | DELETE,
        },
        grfAccessMode: SET_ACCESS,
        grfInheritance: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_GROUP,
            ptstrName: sid.cast(),
        },
    };
    let mut new_dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `entry` points at the live SID owned by `self`; `old_dacl` is
    // part of the live descriptor, and `new_dacl` is a local output pointer.
    let status = unsafe { SetEntriesInAclW(1, &entry, old_dacl, &mut new_dacl) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _new_dacl = LocalBlock(new_dacl.cast());
    // SAFETY: the path, descriptor and new DACL all stay live for this call;
    // only the object's DACL is changed, preserving its owner and other ACLs.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr().cast_mut(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_dacl,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

fn hresult_error(hr: i32) -> io::Error {
    if ((hr as u32 >> 16) & 0x1fff) == 7 {
        io::Error::from_raw_os_error((hr as u32 & 0xffff) as i32)
    } else {
        io::Error::other(format!("HRESULT 0x{:08X}", hr as u32))
    }
}

struct LocalBlock(*mut std::ffi::c_void);

impl Drop for LocalBlock {
    fn drop(&mut self) {
        // SAFETY: the block is allocated by GetNamedSecurityInfoW or
        // SetEntriesInAclW and is freed exactly once with LocalFree.
        unsafe { LocalFree(self.0) };
    }
}

impl std::fmt::Debug for AppContainerProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppContainerProfile")
            .field("sid", &self.sid)
            .field("capability_count", &self.capability_attributes.len())
            .field("created", &self.created)
            .finish()
    }
}

struct AppContainerSid(PSID);

impl std::fmt::Debug for AppContainerSid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AppContainerSid").field(&self.0).finish()
    }
}

impl Drop for AppContainerSid {
    fn drop(&mut self) {
        // SAFETY: both AppContainer profile APIs allocate the returned SID
        // with the allocator paired with FreeSid, and this wrapper owns it.
        unsafe { FreeSid(self.0) };
    }
}

struct DerivedCapability {
    capability_sids: Vec<PSID>,
    capability_array: *mut PSID,
    group_sids: Vec<PSID>,
    group_array: *mut PSID,
}

impl DerivedCapability {
    fn from_name(name: &str) -> io::Result<Self> {
        let name = wide_null(name)?;
        if name.len() <= 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "capability names must not be empty",
            ));
        }
        let mut group_array = ptr::null_mut();
        let mut group_count = 0_u32;
        let mut capability_array = ptr::null_mut();
        let mut capability_count = 0_u32;
        // SAFETY: the name is NUL-terminated and all output pointers refer to
        // initialized locals. The API allocations are owned and freed below.
        if unsafe {
            DeriveCapabilitySidsFromName(
                name.as_ptr(),
                &mut group_array,
                &mut group_count,
                &mut capability_array,
                &mut capability_count,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            // SAFETY: failure may still leave one or both API output pointer
            // arrays populated; free every returned array block.
            if !group_array.is_null() {
                // SAFETY: this is an API output allocation from the failed call.
                unsafe { LocalFree(group_array.cast()) };
            }
            if !capability_array.is_null() {
                // SAFETY: this is an API output allocation from the failed call.
                unsafe { LocalFree(capability_array.cast()) };
            }
            return Err(error);
        }

        let capability_sids = if capability_count == 0 || capability_array.is_null() {
            Vec::new()
        } else {
            // SAFETY: Windows returned `capability_count` entries in this array.
            unsafe { std::slice::from_raw_parts(capability_array, capability_count as usize) }
                .to_vec()
        };
        let group_sids = if group_count == 0 || group_array.is_null() {
            Vec::new()
        } else {
            // SAFETY: Windows returned `group_count` entries in this array.
            unsafe { std::slice::from_raw_parts(group_array, group_count as usize) }.to_vec()
        };
        let derived = Self {
            capability_sids,
            capability_array,
            group_sids,
            group_array,
        };
        if capability_count == 0 || capability_array.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows resolved no capability SIDs",
            ));
        }
        Ok(derived)
    }
}

impl Drop for DerivedCapability {
    fn drop(&mut self) {
        for sid in self.capability_sids.iter().chain(&self.group_sids) {
            if !sid.is_null() {
                // SAFETY: DeriveCapabilitySidsFromName returned each SID as
                // a separately owned LocalAlloc block.
                unsafe { LocalFree((*sid).cast()) };
            }
        }
        if !self.capability_array.is_null() {
            // SAFETY: this is the LocalAlloc pointer array from the API.
            unsafe { LocalFree(self.capability_array.cast()) };
        }
        if !self.group_array.is_null() {
            // SAFETY: this is the LocalAlloc pointer array from the API.
            unsafe { LocalFree(self.group_array.cast()) };
        }
    }
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AppContainerProfile>();
    assert_send_sync::<crate::Launch<'static>>();
};

#[cfg(test)]
mod tests {
    use super::hresult_error;

    #[test]
    fn win32_hresult_preserves_the_win32_error_code() {
        let error = hresult_error(0x8007_0005_u32 as i32);
        assert_eq!(error.raw_os_error(), Some(5));
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn non_win32_hresult_keeps_its_hexadecimal_identity() {
        let error = hresult_error(0x8000_ffff_u32 as i32);
        assert_eq!(error.raw_os_error(), None);
        assert!(error.to_string().contains("HRESULT 0x8000FFFF"));
    }
}
