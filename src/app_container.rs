//! AppContainer profiles and the process-creation capability attribute.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::ptr;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Globalization::lstrlenW;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    DeriveCapabilitySidsFromName, FreeSid, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
};

use crate::wide::wide_null;

const PROFILE_ALREADY_EXISTS: u32 = 0x8007_00b7;
const SE_GROUP_ENABLED: u32 = 0x0000_0004;

/// A named AppContainer profile and the capabilities assigned to its child
/// processes. Profile data persists in Windows after this value is dropped.
pub struct AppContainerProfile {
    sid: AppContainerSid,
    _capabilities: Vec<DerivedCapability>,
    capability_attributes: Vec<SID_AND_ATTRIBUTES>,
}

impl AppContainerProfile {
    /// Creates or opens a named AppContainer profile with no capabilities.
    ///
    /// With no capabilities, the profile receives no optional network or
    /// device access. The name must be unique to the application and at most
    /// 64 UTF-16 code units, as required by Windows.
    pub fn create_or_open(name: &str, display_name: &str, description: &str) -> io::Result<Self> {
        Self::create_or_open_with_capabilities(name, display_name, description, &[])
    }

    /// Creates or opens a named AppContainer profile and grants the named
    /// Windows capabilities to processes launched in it.
    ///
    /// Every capability must resolve successfully. An unknown capability
    /// fails the call rather than silently launching a less capable profile.
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
                    Attributes: SE_GROUP_ENABLED,
                }
            }));
        }

        let mut sid = ptr::null_mut();
        // SAFETY: all UTF-16 strings and capability attributes remain live
        // across the call; `sid` is a local out pointer. Windows returns the
        // profile SID allocation owned by `AppContainerSid`.
        let created = unsafe {
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
        if created as u32 == PROFILE_ALREADY_EXISTS {
            // SAFETY: the profile name is valid and NUL-terminated; `sid` is
            // a local out pointer whose allocation is freed with FreeSid.
            let derived =
                unsafe { DeriveAppContainerSidFromAppContainerName(name_w.as_ptr(), &mut sid) };
            if derived < 0 {
                return Err(io::Error::from_raw_os_error(derived));
            }
        } else if created < 0 {
            return Err(io::Error::from_raw_os_error(created));
        }
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
        })
    }

    /// The profile's SID in standard string form, for ACLs granting the
    /// container access to selected files or directories.
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

impl std::fmt::Debug for AppContainerProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppContainerProfile")
            .field("sid", &self.sid)
            .field("capability_count", &self.capability_attributes.len())
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
            // SAFETY: failure may still leave one or both API output
            // allocations populated; free every returned block.
            if !group_array.is_null() {
                // SAFETY: this is an API output allocation from the failed call.
                unsafe { LocalFree(group_array.cast()) };
            }
            if !capability_array.is_null() {
                // SAFETY: this is an API output allocation from the failed call.
                unsafe { LocalFree(capability_array.cast()) };
            }
            return Err(io::Error::last_os_error());
        }
        if capability_count == 0 || capability_array.is_null() {
            // SAFETY: successful derivation returned this LocalAlloc array.
            unsafe { LocalFree(group_array.cast()) };
            // SAFETY: successful derivation returned this LocalAlloc array.
            unsafe { LocalFree(capability_array.cast()) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows resolved no capability SIDs",
            ));
        }
        // SAFETY: Windows returned `capability_count` entries in this array.
        let capability_sids =
            unsafe { std::slice::from_raw_parts(capability_array, capability_count as usize) }
                .to_vec();
        let group_sids = if group_count == 0 || group_array.is_null() {
            Vec::new()
        } else {
            // SAFETY: Windows returned `group_count` entries in this array.
            unsafe { std::slice::from_raw_parts(group_array, group_count as usize).to_vec() }
        };
        Ok(Self {
            capability_sids,
            capability_array,
            group_sids,
            group_array,
        })
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

const _: () = assert!(size_of::<SECURITY_CAPABILITIES>() > 0);
