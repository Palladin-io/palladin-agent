use std::io;
use std::mem::{size_of, size_of_val};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use thiserror::Error;
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, FreeSid, GetTokenInformation, LookupAccountNameW,
    PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SECURITY_ATTRIBUTES, SID_NAME_USE,
    TOKEN_APPCONTAINER_INFORMATION, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER, TokenAppContainerSid,
    TokenGroups, TokenIsAppContainer, TokenSessionId, TokenUser, WinLocalServiceSid,
};
use windows_sys::Win32::Storage::Packaging::Appx::GetPackageFamilyNameFromToken;
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, ImpersonateNamedPipeClient,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfig2W, SC_MANAGER_CONNECT,
    SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_QUERY_CONFIG, SERVICE_SID_INFO,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
};

use crate::{PIPE_NAME, SERVICE_NAME, WORKER_FILE_NAME};

const SERVICE_SID_TYPE_RESTRICTED_VALUE: u32 = 3;

#[derive(Debug, Error)]
pub enum WindowsBrokerError {
    #[error("Windows broker package family is not embedded in this build")]
    MissingPackageFamily,
    #[error("Windows broker is not running as LocalService with its service SID")]
    WrongServiceIdentity,
    #[error("Windows service is not configured with a restricted service SID")]
    ServiceSidNotRestricted,
    #[error("named-pipe caller is not the expected AppContainer package")]
    CallerNotAuthorized,
    #[error("named-pipe server is not the restricted Palladin Windows service")]
    ServerNotAuthorized,
    #[error("broker-owned worker path is invalid")]
    InvalidWorkerPath,
    #[error("Windows broker operating-system check failed")]
    OperatingSystem,
    #[error("Windows broker transport failed")]
    Transport(#[from] io::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedCaller {
    pub user_sid: String,
    pub session_id: u32,
    pub package_family_name: String,
}

pub fn expected_package_family_name() -> Result<&'static str, WindowsBrokerError> {
    option_env!("PALLADIN_WINDOWS_PACKAGE_FAMILY_NAME")
        .filter(|value| !value.is_empty())
        .ok_or(WindowsBrokerError::MissingPackageFamily)
}

/// Ensures the worker comes from the immutable broker installation root. The
/// client never supplies either path.
pub fn trusted_worker_path(install_root: &Path) -> Result<PathBuf, WindowsBrokerError> {
    if !install_root.is_absolute() {
        return Err(WindowsBrokerError::InvalidWorkerPath);
    }
    let worker = install_root.join(WORKER_FILE_NAME);
    if worker.parent() != Some(install_root) {
        return Err(WindowsBrokerError::InvalidWorkerPath);
    }
    Ok(worker)
}

pub fn companion_alias_path() -> Result<PathBuf, WindowsBrokerError> {
    Ok(known_folder_path(&FOLDERID_LocalAppData)?
        .join("Microsoft")
        .join("WindowsApps")
        .join("palladin-runtime-companion.exe"))
}

pub fn program_data_path() -> Result<PathBuf, WindowsBrokerError> {
    known_folder_path(&FOLDERID_ProgramData)
}

fn known_folder_path(folder_id: &windows_sys::core::GUID) -> Result<PathBuf, WindowsBrokerError> {
    let mut raw = null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(folder_id, KF_FLAG_DEFAULT as u32, null_mut(), &mut raw) };
    if result < 0 || raw.is_null() {
        return Err(WindowsBrokerError::OperatingSystem);
    }
    let length = unsafe { (0..).take_while(|index| *raw.add(*index) != 0).count() };
    let path = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map(PathBuf::from)
        .map_err(|_| WindowsBrokerError::OperatingSystem);
    unsafe { windows_sys::Win32::System::Com::CoTaskMemFree(raw.cast()) };
    path
}

pub fn attest_service_identity() -> Result<(), WindowsBrokerError> {
    unsafe {
        let token = process_token(GetCurrentProcess())?;
        let service_sid = lookup_service_sid()?;
        let result = token_user_is_local_service(token)
            .and_then(|valid| {
                valid
                    .then_some(())
                    .ok_or(WindowsBrokerError::WrongServiceIdentity)
            })
            .and_then(|()| token_contains_group(token, service_sid.as_ptr() as PSID))
            .and_then(|valid| {
                valid
                    .then_some(())
                    .ok_or(WindowsBrokerError::WrongServiceIdentity)
            })
            .and_then(|()| service_sid_is_restricted());
        CloseHandle(token);
        result
    }
}

/// Creates an AppContainer-addressable local named pipe with an explicit DACL.
/// The DACL grants no Everyone or Anonymous access; the connected token is
/// still authenticated before the first frame is read.
pub fn create_local_pipe(first_instance: bool) -> Result<NamedPipeServer, WindowsBrokerError> {
    let expected_pfn = expected_package_family_name()?;
    let package_sid = derive_app_container_sid(expected_pfn)?;
    let service_sid = lookup_service_sid()?;
    let package_sid_text = sid_to_string(package_sid.as_ptr() as PSID)?;
    let service_sid_text = sid_to_string(service_sid.as_ptr() as PSID)?;
    let sddl = format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;LS)(A;;GRGW;;;{service_sid_text})(A;;GRGW;;;{package_sid_text})"
    );
    let descriptor = SecurityDescriptor::from_sddl(&sddl)?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true);
    unsafe {
        options
            .create_with_security_attributes_raw(PIPE_NAME, (&raw mut attributes).cast())
            .map_err(WindowsBrokerError::Transport)
    }
}

/// Authenticates the effective named-pipe token. PID/package inspection is
/// performed only as a second, race-resistant consistency check while the
/// process handle remains open.
pub fn authenticate_connected_caller(
    pipe: &NamedPipeServer,
) -> Result<AuthenticatedCaller, WindowsBrokerError> {
    let expected = expected_package_family_name()?;
    let expected_sid = derive_app_container_sid(expected)?;
    let pipe_handle = pipe.as_raw_handle() as HANDLE;
    let authoritative = unsafe {
        if ImpersonateNamedPipeClient(pipe_handle) == 0 {
            return Err(WindowsBrokerError::CallerNotAuthorized);
        }
        let guard = ImpersonationGuard { active: true };
        let token = thread_token()?;
        let result = authenticate_token(token, expected, expected_sid.as_ptr() as PSID);
        CloseHandle(token);
        guard.revert()?;
        result
    }?;
    authenticate_process_consistency(pipe_handle, expected)?;
    Ok(authoritative)
}

/// Prevents a same-user process from pre-creating the public pipe name and
/// collecting request input. The companion sends no frame until the server is
/// proven to run as LocalService with the exact Palladin restricted service SID.
pub fn authenticate_connected_server(pipe: &NamedPipeClient) -> Result<(), WindowsBrokerError> {
    let pipe_handle = pipe.as_raw_handle() as HANDLE;
    unsafe {
        let mut process_id = 0_u32;
        if GetNamedPipeServerProcessId(pipe_handle, &mut process_id) == 0 || process_id == 0 {
            return Err(WindowsBrokerError::ServerNotAuthorized);
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id);
        if process.is_null() || process == INVALID_HANDLE_VALUE {
            return Err(WindowsBrokerError::ServerNotAuthorized);
        }
        let token = process_token(process);
        let result = token.and_then(|token| {
            let service_sid = lookup_service_sid()?;
            let result = token_user_is_local_service(token)
                .and_then(|valid| {
                    valid
                        .then_some(())
                        .ok_or(WindowsBrokerError::ServerNotAuthorized)
                })
                .and_then(|()| token_contains_group(token, service_sid.as_ptr() as PSID))
                .and_then(|valid| {
                    valid
                        .then_some(())
                        .ok_or(WindowsBrokerError::ServerNotAuthorized)
                })
                .and_then(|()| service_sid_is_restricted());
            CloseHandle(token);
            result
        });
        CloseHandle(process);
        result
    }
}

unsafe fn authenticate_token(
    token: HANDLE,
    expected_pfn: &str,
    expected_appcontainer_sid: PSID,
) -> Result<AuthenticatedCaller, WindowsBrokerError> {
    if !unsafe { token_is_app_container(token)? } {
        return Err(WindowsBrokerError::CallerNotAuthorized);
    }
    let appcontainer = unsafe { token_information(token, TokenAppContainerSid)? };
    let appcontainer = unsafe {
        &*(appcontainer
            .as_ptr()
            .cast::<TOKEN_APPCONTAINER_INFORMATION>())
    };
    if appcontainer.TokenAppContainer.is_null()
        || unsafe { EqualSid(appcontainer.TokenAppContainer, expected_appcontainer_sid) } == 0
    {
        return Err(WindowsBrokerError::CallerNotAuthorized);
    }
    let pfn = unsafe { package_family_from_token(token)? };
    if pfn != expected_pfn {
        return Err(WindowsBrokerError::CallerNotAuthorized);
    }
    let user = unsafe { token_information(token, TokenUser)? };
    let user = unsafe { &*(user.as_ptr().cast::<TOKEN_USER>()) };
    let session = unsafe { token_information(token, TokenSessionId)? };
    let session_id = unsafe { *session.as_ptr().cast::<u32>() };
    Ok(AuthenticatedCaller {
        user_sid: sid_to_string(user.User.Sid)?,
        session_id,
        package_family_name: pfn,
    })
}

fn authenticate_process_consistency(
    pipe: HANDLE,
    expected_pfn: &str,
) -> Result<(), WindowsBrokerError> {
    unsafe {
        let mut process_id = 0_u32;
        if GetNamedPipeClientProcessId(pipe, &mut process_id) == 0 || process_id == 0 {
            return Err(WindowsBrokerError::CallerNotAuthorized);
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id);
        if process.is_null() || process == INVALID_HANDLE_VALUE {
            return Err(WindowsBrokerError::CallerNotAuthorized);
        }
        let token = process_token(process);
        let result = token.and_then(|token| {
            let result = package_family_from_token(token).and_then(|pfn| {
                (pfn == expected_pfn)
                    .then_some(())
                    .ok_or(WindowsBrokerError::CallerNotAuthorized)
            });
            CloseHandle(token);
            result
        });
        CloseHandle(process);
        result
    }
}

struct ImpersonationGuard {
    active: bool,
}

impl ImpersonationGuard {
    fn revert(mut self) -> Result<(), WindowsBrokerError> {
        if unsafe { RevertToSelf() } == 0 {
            // Continuing as an untrusted caller would let its token influence
            // all later service-owned filesystem and process operations.
            std::process::abort();
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active && unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, WindowsBrokerError> {
        let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(WindowsBrokerError::OperatingSystem);
        }
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct AlignedBuffer {
    words: Vec<usize>,
    byte_len: usize,
}

impl AlignedBuffer {
    fn zeroed(byte_len: usize) -> Self {
        let words = byte_len.div_ceil(size_of::<usize>());
        Self {
            words: vec![0; words],
            byte_len,
        }
    }

    fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr().cast()
    }

    fn copy_from(&mut self, bytes: &[u8]) {
        assert_eq!(self.byte_len, bytes.len());
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.as_mut_ptr(), bytes.len());
        }
    }
}

struct OwnedSid(AlignedBuffer);

impl OwnedSid {
    fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
}

fn derive_app_container_sid(name: &str) -> Result<OwnedSid, WindowsBrokerError> {
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut sid = null_mut();
    let result = unsafe { DeriveAppContainerSidFromAppContainerName(wide.as_ptr(), &mut sid) };
    if result < 0 || sid.is_null() {
        return Err(WindowsBrokerError::OperatingSystem);
    }
    let length = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) } as usize;
    if length == 0 {
        unsafe { FreeSid(sid) };
        return Err(WindowsBrokerError::OperatingSystem);
    }
    let bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) };
    let mut owned = AlignedBuffer::zeroed(length);
    owned.copy_from(bytes);
    unsafe { FreeSid(sid) };
    Ok(OwnedSid(owned))
}

fn lookup_service_sid() -> Result<OwnedSid, WindowsBrokerError> {
    let account: Vec<u16> = format!("NT SERVICE\\{SERVICE_NAME}")
        .encode_utf16()
        .chain([0])
        .collect();
    let mut sid_length = 0_u32;
    let mut domain_length = 0_u32;
    let mut use_type: SID_NAME_USE = 0;
    unsafe {
        LookupAccountNameW(
            null(),
            account.as_ptr(),
            null_mut(),
            &mut sid_length,
            null_mut(),
            &mut domain_length,
            &mut use_type,
        );
    }
    if sid_length == 0 {
        return Err(WindowsBrokerError::OperatingSystem);
    }
    let mut sid = AlignedBuffer::zeroed(sid_length as usize);
    let mut domain = vec![0_u16; domain_length as usize];
    if unsafe {
        LookupAccountNameW(
            null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_length,
            domain.as_mut_ptr(),
            &mut domain_length,
            &mut use_type,
        )
    } == 0
    {
        return Err(WindowsBrokerError::OperatingSystem);
    }
    Ok(OwnedSid(sid))
}

fn sid_to_string(sid: PSID) -> Result<String, WindowsBrokerError> {
    let mut value = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 || value.is_null() {
        return Err(WindowsBrokerError::OperatingSystem);
    }
    let length = unsafe { (0..).take_while(|index| *value.add(*index) != 0).count() };
    let string = String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
        .map_err(|_| WindowsBrokerError::OperatingSystem);
    unsafe { LocalFree(value.cast()) };
    string
}

unsafe fn process_token(process: HANDLE) -> Result<HANDLE, WindowsBrokerError> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
        return Err(WindowsBrokerError::OperatingSystem);
    }
    Ok(token)
}

unsafe fn thread_token() -> Result<HANDLE, WindowsBrokerError> {
    let mut token = null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) } == 0
        || token.is_null()
    {
        return Err(WindowsBrokerError::CallerNotAuthorized);
    }
    Ok(token)
}

unsafe fn token_is_app_container(token: HANDLE) -> Result<bool, WindowsBrokerError> {
    let mut value = 0_u32;
    let mut returned = 0_u32;
    if unsafe {
        GetTokenInformation(
            token,
            TokenIsAppContainer,
            (&raw mut value).cast(),
            size_of_val(&value) as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(WindowsBrokerError::OperatingSystem);
    }
    Ok(value != 0)
}

unsafe fn package_family_from_token(token: HANDLE) -> Result<String, WindowsBrokerError> {
    let mut length = 0_u32;
    if unsafe { GetPackageFamilyNameFromToken(token, &mut length, null_mut()) }
        != ERROR_INSUFFICIENT_BUFFER
        || length == 0
    {
        return Err(WindowsBrokerError::CallerNotAuthorized);
    }
    let mut family = vec![0_u16; length as usize];
    if unsafe { GetPackageFamilyNameFromToken(token, &mut length, family.as_mut_ptr()) } != 0 {
        return Err(WindowsBrokerError::CallerNotAuthorized);
    }
    family.truncate(
        family
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(family.len()),
    );
    String::from_utf16(&family).map_err(|_| WindowsBrokerError::CallerNotAuthorized)
}

unsafe fn token_user_is_local_service(token: HANDLE) -> Result<bool, WindowsBrokerError> {
    let token_user = unsafe { token_information(token, TokenUser)? };
    let user = unsafe { &*(token_user.as_ptr().cast::<TOKEN_USER>()) };
    // `CreateWellKnownSid` requires a SID-aligned destination, so do not use a
    // byte array even though the payload itself is byte-addressed.
    let mut local_service_sid = [0_usize; 9];
    let mut sid_size = size_of_val(&local_service_sid) as u32;
    if unsafe {
        CreateWellKnownSid(
            WinLocalServiceSid,
            null_mut(),
            local_service_sid.as_mut_ptr().cast(),
            &mut sid_size,
        )
    } == 0
    {
        return Err(WindowsBrokerError::OperatingSystem);
    }
    Ok(unsafe { EqualSid(user.User.Sid, local_service_sid.as_mut_ptr().cast()) } != 0)
}

unsafe fn token_contains_group(token: HANDLE, sid: PSID) -> Result<bool, WindowsBrokerError> {
    let groups = unsafe { token_information(token, TokenGroups)? };
    let header = unsafe { &*(groups.as_ptr().cast::<TOKEN_GROUPS>()) };
    let first = header.Groups.as_ptr();
    for index in 0..header.GroupCount as usize {
        if unsafe { EqualSid((*first.add(index)).Sid, sid) } != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

unsafe fn token_information(
    token: HANDLE,
    class: i32,
) -> Result<AlignedBuffer, WindowsBrokerError> {
    let mut length = 0_u32;
    unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut length) };
    if length == 0 {
        return Err(WindowsBrokerError::OperatingSystem);
    }
    let mut buffer = AlignedBuffer::zeroed(length as usize);
    if unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(WindowsBrokerError::OperatingSystem);
    }
    Ok(buffer)
}

unsafe fn service_sid_is_restricted() -> Result<(), WindowsBrokerError> {
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(WindowsBrokerError::OperatingSystem);
    }
    let service_name: Vec<u16> = SERVICE_NAME.encode_utf16().chain([0]).collect();
    let service = unsafe { OpenServiceW(manager, service_name.as_ptr(), SERVICE_QUERY_CONFIG) };
    if service.is_null() {
        unsafe { CloseServiceHandle(manager) };
        return Err(WindowsBrokerError::OperatingSystem);
    }
    let mut info = SERVICE_SID_INFO::default();
    let mut needed = 0_u32;
    let queried = unsafe {
        QueryServiceConfig2W(
            service,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            (&raw mut info).cast(),
            size_of::<SERVICE_SID_INFO>() as u32,
            &mut needed,
        )
    };
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    if queried == 0 || info.dwServiceSidType != SERVICE_SID_TYPE_RESTRICTED_VALUE {
        return Err(WindowsBrokerError::ServiceSidNotRestricted);
    }
    Ok(())
}
