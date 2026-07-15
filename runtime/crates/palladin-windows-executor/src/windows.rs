use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString, c_void};
use std::fs::File;
use std::io::{self, Read as _, Write};
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use windows::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, LocalFree, SetHandleInformation, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, GetAppContainerFolderPath,
};
use windows::Win32::Security::{
    DeriveCapabilitySidsFromName, FreeSid, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES,
    SID_AND_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FileAttributeTagInfo, GetFileInformationByHandleEx, OPEN_EXISTING,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    ExecutorError, ExecutorRequest, MAX_REQUEST_BYTES, SecretVariable,
    validate_windows_secret_environment_names,
};

const APPCONTAINER_NAME_PREFIX: &str = "Palladin.Runtime.Executor.v1";
const APPCONTAINER_DISPLAY_NAME: &str = "Palladin Hardened Executor";
const INTERNET_CLIENT_CAPABILITY: &str = "internetClient";
const CHILD_MACHINE_ENVIRONMENT: &[&str] =
    &["PATH", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432"];

pub(super) fn run_executor_from_standard_input() -> Result<i32, ExecutorError> {
    if std::env::args_os().len() != 1 {
        return Err(ExecutorError::InvalidRequest);
    }
    let request = read_request()?;
    execute(request)
}

fn read_request() -> Result<ExecutorRequest, ExecutorError> {
    let mut length = [0_u8; 4];
    io::stdin()
        .read_exact(&mut length)
        .map_err(|_| ExecutorError::InvalidRequest)?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| ExecutorError::InvalidRequest)?;
    if length == 0 || length > MAX_REQUEST_BYTES {
        return Err(ExecutorError::InvalidRequest);
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    io::stdin()
        .read_exact(&mut payload)
        .map_err(|_| ExecutorError::InvalidRequest)?;
    let mut trailing = [0_u8; 1];
    if io::stdin()
        .read(&mut trailing)
        .map_err(|_| ExecutorError::InvalidRequest)?
        != 0
    {
        return Err(ExecutorError::InvalidRequest);
    }
    serde_json::from_slice(&payload).map_err(|_| ExecutorError::InvalidRequest)
}

fn execute(request: ExecutorRequest) -> Result<i32, ExecutorError> {
    let capability = CapabilitySid::derive(INTERNET_CLIENT_CAPABILITY)?;
    let capability_attributes = [SID_AND_ATTRIBUTES {
        Sid: capability.sid(),
        Attributes: 4,
    }];
    let profile = AppContainerProfile::create(&capability_attributes)?;
    let profile_root = profile.folder()?;
    let temporary = match &request {
        ExecutorRequest::Command { .. } => None,
        ExecutorRequest::Script { script, .. } => {
            Some(PrivateScript::new(&profile_root, script.as_bytes())?)
        }
    };
    let (mut command, environment) = match &request {
        ExecutorRequest::Command {
            command,
            environment,
        } => (command.clone(), environment.as_slice()),
        ExecutorRequest::Script {
            interpreter,
            environment,
            ..
        } => (
            vec![
                interpreter.to_string_lossy().into_owned(),
                temporary
                    .as_ref()
                    .ok_or(ExecutorError::TemporaryScript)?
                    .path()
                    .to_string_lossy()
                    .into_owned(),
            ],
            environment.as_slice(),
        ),
    };
    let executable = PinnedExecutable::resolve(
        command
            .first()
            .ok_or(ExecutorError::ExecutableUnavailable)?,
    )?;
    command[0] = executable.path().to_string_lossy().into_owned();
    let environment = build_environment(environment, &profile_root)?;
    let exit_code = launch_appcontainer(
        &executable,
        &command,
        &environment,
        &profile_root,
        profile.sid(),
        &capability_attributes,
    );
    drop(request);
    drop(environment);
    if let Some(temporary) = temporary {
        temporary.close()?;
    }
    exit_code
}

fn launch_appcontainer(
    executable: &PinnedExecutable,
    arguments: &[String],
    environment: &[u16],
    current_directory: &Path,
    appcontainer_sid: PSID,
    capabilities: &[SID_AND_ATTRIBUTES],
) -> Result<i32, ExecutorError> {
    let mut standard_output = ChildPipe::new()?;
    let mut standard_error = ChildPipe::new()?;
    let standard_input = open_null_input()?;
    set_inheritable(&standard_input, true)?;
    let inherited_handles = [
        raw_handle(&standard_input),
        standard_output.child_handle(),
        standard_error.child_handle(),
    ];

    let mut security_capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: appcontainer_sid,
        Capabilities: capabilities.as_ptr().cast_mut(),
        CapabilityCount: u32::try_from(capabilities.len())
            .map_err(|_| ExecutorError::Containment)?,
        Reserved: 0,
    };
    let mut attributes = AttributeList::new(2)?;
    attributes.update(
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
        (&mut security_capabilities as *mut SECURITY_CAPABILITIES).cast(),
        size_of::<SECURITY_CAPABILITIES>(),
    )?;
    attributes.update(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
        inherited_handles.as_ptr().cast(),
        size_of_val(&inherited_handles),
    )?;

    let job = create_kill_job()?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb =
        u32::try_from(size_of::<STARTUPINFOEXW>()).map_err(|_| ExecutorError::Containment)?;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited_handles[0];
    startup.StartupInfo.hStdOutput = inherited_handles[1];
    startup.StartupInfo.hStdError = inherited_handles[2];
    startup.lpAttributeList = attributes.as_raw();

    let application = wide_null(executable.path().as_os_str())?;
    let mut command_line = wide_null(OsStr::new(&windows_command_line(arguments)))?;
    let directory = wide_null(current_directory.as_os_str())?;
    let mut information = PROCESS_INFORMATION::default();
    // SAFETY: all pointers refer to live, correctly sized Windows structures and
    // null-terminated UTF-16 buffers for the duration of CreateProcessW. The
    // handle list contains only the three explicitly inheritable stdio handles.
    unsafe {
        CreateProcessW(
            PCWSTR(application.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            Some(environment.as_ptr().cast::<c_void>()),
            PCWSTR(directory.as_ptr()),
            (&raw const startup.StartupInfo).cast(),
            &mut information,
        )
        .map_err(|_| ExecutorError::Spawn)?;
    }
    let process = unsafe { owned_handle(information.hProcess)? };
    let thread = unsafe { owned_handle(information.hThread)? };
    // Close our copies of the child's pipe endpoints before readers wait for EOF.
    standard_output.close_child();
    standard_error.close_child();
    drop(standard_input);

    // SAFETY: process and job handles are valid and the process is still suspended,
    // so no uncontained user code can run before assignment succeeds.
    unsafe {
        if AssignProcessToJobObject(raw_handle(&job), raw_handle(&process)).is_err() {
            terminate_suspended_process(&process);
            return Err(ExecutorError::Containment);
        }
        if ResumeThread(raw_handle(&thread)) == u32::MAX {
            terminate_suspended_process(&process);
            return Err(ExecutorError::Containment);
        }
    }
    drop(thread);

    let output_reader = standard_output.take_parent()?;
    let error_reader = standard_error.take_parent()?;
    let output = std::thread::spawn(move || forward(output_reader, io::stdout()));
    let errors = std::thread::spawn(move || forward(error_reader, io::stderr()));

    // SAFETY: the process handle remains owned until after the wait and status read.
    let waited = unsafe { WaitForSingleObject(raw_handle(&process), INFINITE) };
    if waited != WAIT_OBJECT_0 {
        return Err(ExecutorError::Wait);
    }
    let mut exit_code = 0_u32;
    unsafe {
        GetExitCodeProcess(raw_handle(&process), &mut exit_code)
            .map_err(|_| ExecutorError::Wait)?;
    }
    // Closing the kill-on-close Job before waiting for EOF terminates any
    // descendants that inherited or duplicated the output handles. Otherwise a
    // child can exit while a grandchild keeps the readers blocked indefinitely.
    drop(process);
    drop(job);
    output.join().map_err(|_| ExecutorError::Output)??;
    errors.join().map_err(|_| ExecutorError::Output)??;
    Ok(i32::from_ne_bytes(exit_code.to_ne_bytes()))
}

unsafe fn terminate_suspended_process(process: &OwnedHandle) {
    let _ = unsafe { TerminateProcess(raw_handle(process), 125) };
    let _ = unsafe { WaitForSingleObject(raw_handle(process), 5_000) };
}

fn forward(mut input: File, mut output: impl Write) -> Result<(), ExecutorError> {
    io::copy(&mut input, &mut output).map_err(|_| ExecutorError::Output)?;
    output.flush().map_err(|_| ExecutorError::Output)
}

fn create_kill_job() -> Result<OwnedHandle, ExecutorError> {
    let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
        .map_err(|_| ExecutorError::Containment)?;
    let job = unsafe { owned_handle(job)? };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    unsafe {
        SetInformationJobObject(
            raw_handle(&job),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .map_err(|_| ExecutorError::Containment)?,
        )
        .map_err(|_| ExecutorError::Containment)?;
    }
    Ok(job)
}

struct ChildPipe {
    parent: Option<OwnedHandle>,
    child: Option<OwnedHandle>,
}

impl ChildPipe {
    fn new() -> Result<Self, ExecutorError> {
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| ExecutorError::Containment)?,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: true.into(),
        };
        let mut parent = HANDLE::default();
        let mut child = HANDLE::default();
        unsafe {
            CreatePipe(&mut parent, &mut child, Some(&raw mut attributes), 0)
                .map_err(|_| ExecutorError::Containment)?;
        }
        let parent = unsafe { owned_handle(parent)? };
        let child = unsafe { owned_handle(child)? };
        set_inheritable(&parent, false)?;
        Ok(Self {
            parent: Some(parent),
            child: Some(child),
        })
    }

    fn child_handle(&self) -> HANDLE {
        raw_handle(self.child.as_ref().expect("child pipe handle"))
    }

    fn close_child(&mut self) {
        self.child.take();
    }

    fn take_parent(&mut self) -> Result<File, ExecutorError> {
        let parent = self.parent.take().ok_or(ExecutorError::Containment)?;
        Ok(File::from(parent))
    }
}

fn open_null_input() -> Result<OwnedHandle, ExecutorError> {
    let nul = wide_null(OsStr::new("NUL"))?;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(nul.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|_| ExecutorError::Containment)?;
    unsafe { owned_handle(handle) }
}

fn set_inheritable(handle: &OwnedHandle, inheritable: bool) -> Result<(), ExecutorError> {
    unsafe {
        SetHandleInformation(
            raw_handle(handle),
            HANDLE_FLAG_INHERIT.0,
            if inheritable {
                HANDLE_FLAG_INHERIT
            } else {
                Default::default()
            },
        )
        .map_err(|_| ExecutorError::Containment)
    }
}

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

unsafe fn owned_handle(handle: HANDLE) -> Result<OwnedHandle, ExecutorError> {
    if handle.is_invalid() {
        return Err(ExecutorError::Containment);
    }
    // SAFETY: the caller transfers ownership of a newly returned Win32 handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
}

struct AttributeList {
    storage: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttributeList {
    fn new(count: u32) -> Result<Self, ExecutorError> {
        let mut bytes = 0_usize;
        let _ = unsafe { InitializeProcThreadAttributeList(None, count, None, &mut bytes) };
        if bytes == 0 {
            return Err(ExecutorError::Containment);
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        unsafe {
            InitializeProcThreadAttributeList(Some(list), count, None, &mut bytes)
                .map_err(|_| ExecutorError::Containment)?;
        }
        Ok(Self { storage, list })
    }

    fn update(
        &mut self,
        attribute: usize,
        value: *const c_void,
        bytes: usize,
    ) -> Result<(), ExecutorError> {
        unsafe {
            UpdateProcThreadAttribute(self.list, 0, attribute, Some(value), bytes, None, None)
                .map_err(|_| ExecutorError::Containment)
        }
    }

    fn as_raw(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if !self.list.0.is_null() {
            unsafe { DeleteProcThreadAttributeList(self.list) };
        }
        self.storage.zeroize();
    }
}

struct CapabilitySid {
    sid: PSID,
    group_array: *mut PSID,
    group_count: u32,
    capability_array: *mut PSID,
    capability_count: u32,
}

impl CapabilitySid {
    fn derive(name: &str) -> Result<Self, ExecutorError> {
        let name = wide_null(OsStr::new(name))?;
        let mut group_array = null_mut();
        let mut group_count = 0_u32;
        let mut capability_array = null_mut();
        let mut capability_count = 0_u32;
        unsafe {
            DeriveCapabilitySidsFromName(
                PCWSTR(name.as_ptr()),
                &mut group_array,
                &mut group_count,
                &mut capability_array,
                &mut capability_count,
            )
            .map_err(|_| ExecutorError::AppContainerUnavailable)?;
        }
        if capability_count != 1 || capability_array.is_null() {
            free_sid_array(group_array, group_count);
            free_sid_array(capability_array, capability_count);
            return Err(ExecutorError::AppContainerUnavailable);
        }
        let sid = unsafe { *capability_array };
        Ok(Self {
            sid,
            group_array,
            group_count,
            capability_array,
            capability_count,
        })
    }

    fn sid(&self) -> PSID {
        self.sid
    }
}

impl Drop for CapabilitySid {
    fn drop(&mut self) {
        free_sid_array(self.group_array, self.group_count);
        free_sid_array(self.capability_array, self.capability_count);
    }
}

fn free_sid_array(array: *mut PSID, count: u32) {
    if array.is_null() {
        return;
    }
    for index in 0..count {
        let sid = unsafe { *array.add(index as usize) };
        if !sid.0.is_null() {
            unsafe { LocalFree(Some(HLOCAL(sid.0))) };
        }
    }
    unsafe { LocalFree(Some(HLOCAL(array.cast()))) };
}

struct AppContainerProfile {
    name: String,
    sid: PSID,
}

impl AppContainerProfile {
    fn create(capabilities: &[SID_AND_ATTRIBUTES]) -> Result<Self, ExecutorError> {
        let name = random_appcontainer_name()?;
        let wide_name = wide_null(OsStr::new(&name))?;
        let display = wide_null(OsStr::new(APPCONTAINER_DISPLAY_NAME))?;
        let sid = unsafe {
            CreateAppContainerProfile(
                PCWSTR(wide_name.as_ptr()),
                PCWSTR(display.as_ptr()),
                PCWSTR(display.as_ptr()),
                Some(capabilities),
            )
        }
        .map_err(|_| ExecutorError::AppContainerUnavailable)?;
        Ok(Self { name, sid })
    }

    fn sid(&self) -> PSID {
        self.sid
    }

    fn folder(&self) -> Result<PathBuf, ExecutorError> {
        let mut sid_string = PWSTR::null();
        unsafe {
            ConvertSidToStringSidW(self.sid, &mut sid_string)
                .map_err(|_| ExecutorError::AppContainerUnavailable)?;
        }
        let path = unsafe { GetAppContainerFolderPath(PCWSTR(sid_string.0)) };
        unsafe { LocalFree(Some(HLOCAL(sid_string.0.cast()))) };
        let path = path.map_err(|_| ExecutorError::AppContainerUnavailable)?;
        let value = unsafe { wide_pointer_to_path(path.0) };
        unsafe { CoTaskMemFree(Some(path.0.cast())) };
        value
    }
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        if !self.sid.0.is_null() {
            unsafe {
                let _ = FreeSid(self.sid);
            }
        }
        if let Ok(name) = wide_null(OsStr::new(&self.name)) {
            unsafe {
                let _ = DeleteAppContainerProfile(PCWSTR(name.as_ptr()));
            }
        }
    }
}

fn random_appcontainer_name() -> Result<String, ExecutorError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| ExecutorError::AppContainerUnavailable)?;
    let mut name = String::with_capacity(APPCONTAINER_NAME_PREFIX.len() + 1 + random.len() * 2);
    name.push_str(APPCONTAINER_NAME_PREFIX);
    name.push('.');
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").map_err(|_| ExecutorError::AppContainerUnavailable)?;
    }
    Ok(name)
}

unsafe fn wide_pointer_to_path(pointer: *const u16) -> Result<PathBuf, ExecutorError> {
    if pointer.is_null() {
        return Err(ExecutorError::AppContainerUnavailable);
    }
    let mut length = 0_usize;
    while unsafe { *pointer.add(length) } != 0 {
        length = length
            .checked_add(1)
            .ok_or(ExecutorError::AppContainerUnavailable)?;
        if length > 32_767 {
            return Err(ExecutorError::AppContainerUnavailable);
        }
    }
    let units = unsafe { std::slice::from_raw_parts(pointer, length) };
    Ok(PathBuf::from(OsString::from_wide(units)))
}

struct PrivateScript {
    directory: Option<tempfile::TempDir>,
    file: Option<File>,
    path: PathBuf,
}

impl PrivateScript {
    fn new(profile_root: &Path, contents: &[u8]) -> Result<Self, ExecutorError> {
        let temp_root = profile_root.join("Temp");
        std::fs::create_dir_all(&temp_root).map_err(|_| ExecutorError::TemporaryScript)?;
        let directory = tempfile::Builder::new()
            .prefix("palladin-script-")
            .tempdir_in(temp_root)
            .map_err(|_| ExecutorError::TemporaryScript)?;
        let path = directory.path().join("script");
        let mut options = std::fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_DELETE.0)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE.0);
        let mut file = options
            .open(&path)
            .map_err(|_| ExecutorError::TemporaryScript)?;
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|_| ExecutorError::TemporaryScript)?;
        Ok(Self {
            directory: Some(directory),
            file: Some(file),
            path,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn close(mut self) -> Result<(), ExecutorError> {
        self.file.take();
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(ExecutorError::TemporaryScript),
        }
        self.path.clear();
        if let Some(directory) = self.directory.take() {
            directory
                .close()
                .map_err(|_| ExecutorError::TemporaryScript)?;
        }
        Ok(())
    }
}

impl Drop for PrivateScript {
    fn drop(&mut self) {
        self.file.take();
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn build_environment(
    secrets: &[SecretVariable],
    profile_root: &Path,
) -> Result<Zeroizing<Vec<u16>>, ExecutorError> {
    validate_windows_secret_environment_names(secrets.iter().map(SecretVariable::name))?;
    if secrets.iter().any(|secret| secret.value().contains('\0')) {
        return Err(ExecutorError::InvalidRequest);
    }
    let windows = known_directory(GetWindowsDirectoryW)?;
    let system = known_directory(GetSystemDirectoryW)?;
    let temp = profile_root.join("Temp");
    let mut values = BTreeMap::<String, OsString>::new();
    for name in CHILD_MACHINE_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            values.insert((*name).to_owned(), value);
        }
    }
    values.insert(
        "LOCALAPPDATA".to_owned(),
        profile_root.as_os_str().to_owned(),
    );
    values.insert("TEMP".to_owned(), temp.as_os_str().to_owned());
    values.insert("TMP".to_owned(), temp.as_os_str().to_owned());
    values.insert("SYSTEMROOT".to_owned(), windows.as_os_str().to_owned());
    values.insert("WINDIR".to_owned(), windows.as_os_str().to_owned());
    let inherited_path = values.remove("PATH").unwrap_or_default();
    let mut path_entries = vec![system];
    path_entries.extend(std::env::split_paths(&inherited_path).filter(|path| path.is_absolute()));
    values.insert(
        "PATH".to_owned(),
        std::env::join_paths(path_entries).map_err(|_| ExecutorError::InvalidRequest)?,
    );
    enum EnvironmentValue<'a> {
        Public(&'a OsStr),
        Secret(&'a str),
    }

    // Only names are copied. Secret values are encoded directly from their
    // zeroizing request owners into the final zeroizing UTF-16 block.
    let mut entries = Vec::with_capacity(values.len() + secrets.len());
    entries.extend(
        values
            .iter()
            .map(|(name, value)| (name.clone(), EnvironmentValue::Public(value.as_os_str()))),
    );
    entries.extend(secrets.iter().map(|secret| {
        (
            secret.name().to_ascii_uppercase(),
            EnvironmentValue::Secret(secret.value()),
        )
    }));
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    let mut block = Zeroizing::new(Vec::new());
    for (name, value) in entries {
        block.extend(OsStr::new(&name).encode_wide());
        block.push('=' as u16);
        match value {
            EnvironmentValue::Public(value) => block.extend(value.encode_wide()),
            EnvironmentValue::Secret(value) => block.extend(OsStr::new(value).encode_wide()),
        }
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn known_directory(
    function: unsafe fn(Option<&mut [u16]>) -> u32,
) -> Result<PathBuf, ExecutorError> {
    let mut buffer = vec![0_u16; 32_768];
    let length = unsafe { function(Some(&mut buffer)) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(ExecutorError::AppContainerUnavailable);
    }
    buffer.truncate(length);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

struct PinnedExecutable {
    path: PathBuf,
    _handles: Vec<OwnedHandle>,
}

impl PinnedExecutable {
    fn resolve(value: &str) -> Result<Self, ExecutorError> {
        let lowercase = value.to_ascii_lowercase();
        if value.contains('\0') || lowercase.ends_with(".cmd") || lowercase.ends_with(".bat") {
            return Err(ExecutorError::ExecutableUnavailable);
        }
        let path = Path::new(value);
        if path.is_absolute() {
            Self::pin(path.to_path_buf())
        } else if path.components().count() == 1 {
            let mut name = value.to_owned();
            if Path::new(&name).extension().is_none() {
                name.push_str(".exe");
            }
            let system = known_directory(GetSystemDirectoryW)?;
            let inherited = std::env::var_os("PATH").unwrap_or_default();
            for directory in std::iter::once(system)
                .chain(std::env::split_paths(&inherited).filter(|path| path.is_absolute()))
            {
                if let Ok(executable) = Self::pin(directory.join(&name)) {
                    return Ok(executable);
                }
            }
            Err(ExecutorError::ExecutableUnavailable)
        } else {
            Err(ExecutorError::ExecutableUnavailable)
        }
    }

    fn pin(candidate: PathBuf) -> Result<Self, ExecutorError> {
        let path =
            std::fs::canonicalize(candidate).map_err(|_| ExecutorError::ExecutableUnavailable)?;
        if !path.is_file()
            || !path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        {
            return Err(ExecutorError::ExecutableUnavailable);
        }

        // CreateProcessW reopens the executable by pathname. Keep every named
        // ancestor and the file itself open without FILE_SHARE_DELETE so an
        // untrusted same-user process cannot rename/swap any component between
        // validation and process creation. The second canonicalization proves
        // that the fully pinned chain is the chain we originally inspected.
        let mut ancestors = path
            .ancestors()
            .skip(1)
            .filter(|ancestor| ancestor.file_name().is_some())
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        ancestors.reverse();
        let mut handles = Vec::with_capacity(ancestors.len() + 1);
        for ancestor in ancestors {
            handles.push(open_pinned_path(&ancestor, true)?);
        }
        handles.push(open_pinned_path(&path, false)?);
        let verified =
            std::fs::canonicalize(&path).map_err(|_| ExecutorError::ExecutableUnavailable)?;
        if verified != path {
            return Err(ExecutorError::ExecutableUnavailable);
        }
        Ok(Self {
            path,
            _handles: handles,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn open_pinned_path(path: &Path, directory: bool) -> Result<OwnedHandle, ExecutorError> {
    let wide = wide_null(path.as_os_str())?;
    let flags = if directory {
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    } else {
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
    };
    let access = if directory {
        FILE_READ_ATTRIBUTES.0
    } else {
        FILE_GENERIC_READ.0
    };
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|_| ExecutorError::ExecutableUnavailable)?;
    let handle =
        unsafe { owned_handle(handle) }.map_err(|_| ExecutorError::ExecutableUnavailable)?;
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            raw_handle(&handle),
            FileAttributeTagInfo,
            (&raw mut attributes).cast(),
            u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>())
                .map_err(|_| ExecutorError::ExecutableUnavailable)?,
        )
        .map_err(|_| ExecutorError::ExecutableUnavailable)?;
    }
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(ExecutorError::ExecutableUnavailable);
    }
    Ok(handle)
}

fn windows_command_line(arguments: &[String]) -> String {
    arguments
        .iter()
        .map(|argument| quote_windows_argument(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_windows_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return argument.to_owned();
    }
    let mut quoted = String::from('"');
    let mut backslashes = 0_usize;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            quoted.push('"');
        } else {
            quoted.extend(std::iter::repeat_n('\\', backslashes));
            quoted.push(character);
        }
        backslashes = 0;
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

fn wide_null(value: &OsStr) -> Result<Vec<u16>, ExecutorError> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) || wide.len() >= 32_767 {
        return Err(ExecutorError::InvalidRequest);
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenIsAppContainer};
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_DUP_HANDLE, PROCESS_VM_READ,
    };

    const PROBE_PARENT_PID: &str = "CLAW_TEST_PARENT_PID";
    const PROBE_DENIED_PATH: &str = "CLAW_TEST_DENIED_PATH";
    const PROBE_SCRIPT_PATH: &str = "CLAW_TEST_SCRIPT_PATH";
    const PROBE_SURVIVOR_PATH: &str = "CLAW_TEST_SURVIVOR_PATH";

    #[test]
    fn command_line_quoting_preserves_windows_arguments() {
        assert_eq!(quote_windows_argument("plain"), "plain");
        assert_eq!(quote_windows_argument(""), "\"\"");
        assert_eq!(quote_windows_argument("two words"), "\"two words\"");
        assert_eq!(quote_windows_argument("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quote_windows_argument("tail\\"), "tail\\");
        assert_eq!(quote_windows_argument("tail \\"), "\"tail \\\\\"");
    }

    #[test]
    fn environment_has_only_fixed_os_paths_profile_paths_and_scoped_secrets() {
        let profile = Path::new(r"C:\fixture\profile");
        let secret = SecretVariable {
            name: "CLAW_SECRET".to_owned(),
            value: "fixture".to_owned(),
        };
        let block = build_environment(&[secret], profile).expect("environment");
        let rendered = String::from_utf16_lossy(&block);
        let contains_secret_variable = rendered.contains("CLAW_SECRET=fixture");
        assert!(
            contains_secret_variable,
            "executor environment omitted the scoped credential"
        );
        assert!(rendered.contains("LOCALAPPDATA=C:\\fixture\\profile"));
        assert!(!rendered.contains("NODE_OPTIONS"));
        assert!(!rendered.contains("PALLADIN_BROKER_ROOT"));
    }

    #[test]
    fn appcontainer_denies_parent_process_memory_and_ungranted_storage() {
        let capability = CapabilitySid::derive(INTERNET_CLIENT_CAPABILITY).expect("capability");
        let capabilities = [SID_AND_ATTRIBUTES {
            Sid: capability.sid(),
            Attributes: 4,
        }];
        let profile = AppContainerProfile::create(&capabilities).expect("profile");
        let profile_root = profile.folder().expect("profile folder");
        let probe_path = profile_root.join(format!("palladin-probe-{}.exe", std::process::id()));
        std::fs::copy(
            std::env::current_exe().expect("test executable"),
            &probe_path,
        )
        .expect("copy probe");
        let denied = tempfile::tempdir().expect("denied directory");
        std::fs::write(denied.path().join("broker-ciphertext"), b"fixture")
            .expect("denied fixture");
        let secrets = [
            SecretVariable {
                name: PROBE_PARENT_PID.to_owned(),
                value: std::process::id().to_string(),
            },
            SecretVariable {
                name: PROBE_DENIED_PATH.to_owned(),
                value: denied.path().to_string_lossy().into_owned(),
            },
        ];
        let environment = build_environment(&secrets, &profile_root).expect("environment");
        let executable = PinnedExecutable::resolve(&probe_path.to_string_lossy()).expect("probe");
        let arguments = vec![
            probe_path.to_string_lossy().into_owned(),
            "--exact".to_owned(),
            "windows::tests::appcontainer_probe_helper".to_owned(),
            "--ignored".to_owned(),
        ];
        let exit = launch_appcontainer(
            &executable,
            &arguments,
            &environment,
            &profile_root,
            profile.sid(),
            &capabilities,
        )
        .expect("contained probe");
        drop(executable);
        std::fs::remove_file(probe_path).expect("probe cleanup");
        assert_eq!(exit, 0);
    }

    #[test]
    fn appcontainer_script_is_private_scoped_and_removed_after_execution() {
        let capability = CapabilitySid::derive(INTERNET_CLIENT_CAPABILITY).expect("capability");
        let capabilities = [SID_AND_ATTRIBUTES {
            Sid: capability.sid(),
            Attributes: 4,
        }];
        let profile = AppContainerProfile::create(&capabilities).expect("profile");
        let profile_root = profile.folder().expect("profile folder");
        let probe_path = profile_root.join(format!("palladin-probe-{}.exe", std::process::id()));
        std::fs::copy(
            std::env::current_exe().expect("test executable"),
            &probe_path,
        )
        .expect("copy probe");
        let script =
            PrivateScript::new(&profile_root, b"fixture-script-secret").expect("private script");
        let script_path = script.path().to_path_buf();
        let secrets = [SecretVariable {
            name: PROBE_SCRIPT_PATH.to_owned(),
            value: script_path.to_string_lossy().into_owned(),
        }];
        let environment = build_environment(&secrets, &profile_root).expect("environment");
        let executable = PinnedExecutable::resolve(&probe_path.to_string_lossy()).expect("probe");
        let arguments = vec![
            probe_path.to_string_lossy().into_owned(),
            "--exact".to_owned(),
            "windows::tests::appcontainer_script_probe_helper".to_owned(),
            "--ignored".to_owned(),
        ];
        let exit = launch_appcontainer(
            &executable,
            &arguments,
            &environment,
            &profile_root,
            profile.sid(),
            &capabilities,
        )
        .expect("contained script probe");
        drop(executable);
        script.close().expect("script cleanup");
        assert!(!script_path.exists(), "private script survived execution");
        std::fs::remove_file(probe_path).expect("probe cleanup");
        assert_eq!(exit, 0);
    }

    #[test]
    fn appcontainer_job_kills_descendants_before_waiting_for_output_eof() {
        let capability = CapabilitySid::derive(INTERNET_CLIENT_CAPABILITY).expect("capability");
        let capabilities = [SID_AND_ATTRIBUTES {
            Sid: capability.sid(),
            Attributes: 4,
        }];
        let profile = AppContainerProfile::create(&capabilities).expect("profile");
        let profile_root = profile.folder().expect("profile folder");
        let probe_path = profile_root.join(format!("palladin-probe-{}.exe", std::process::id()));
        std::fs::copy(
            std::env::current_exe().expect("test executable"),
            &probe_path,
        )
        .expect("copy probe");
        let temp = profile_root.join("Temp");
        std::fs::create_dir_all(&temp).expect("profile temp");
        let survivor = temp.join("survived");
        let secrets = [SecretVariable {
            name: PROBE_SURVIVOR_PATH.to_owned(),
            value: survivor.to_string_lossy().into_owned(),
        }];
        let environment = build_environment(&secrets, &profile_root).expect("environment");
        let executable = PinnedExecutable::resolve(&probe_path.to_string_lossy()).expect("probe");
        let arguments = vec![
            probe_path.to_string_lossy().into_owned(),
            "--exact".to_owned(),
            "windows::tests::appcontainer_tree_root_helper".to_owned(),
            "--ignored".to_owned(),
        ];
        let exit = launch_appcontainer(
            &executable,
            &arguments,
            &environment,
            &profile_root,
            profile.sid(),
            &capabilities,
        )
        .expect("contained tree probe");
        assert_eq!(exit, 0);
        std::thread::sleep(std::time::Duration::from_millis(1_500));
        assert!(!survivor.exists(), "a Job descendant survived root exit");
        drop(executable);
        std::fs::remove_file(probe_path).expect("probe cleanup");
    }

    #[test]
    #[ignore = "subprocess helper launched only by the AppContainer boundary test"]
    fn appcontainer_probe_helper() {
        let parent_pid: u32 = std::env::var(PROBE_PARENT_PID)
            .expect("parent pid")
            .parse()
            .expect("numeric parent pid");
        let denied_path = PathBuf::from(std::env::var_os(PROBE_DENIED_PATH).expect("denied path"));
        assert!(process_is_appcontainer());
        let parent =
            unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_DUP_HANDLE, false, parent_pid) };
        assert!(parent.is_err(), "AppContainer opened parent process memory");
        assert!(
            std::fs::read_dir(denied_path).is_err(),
            "AppContainer opened ungranted broker-like storage"
        );
    }

    #[test]
    #[ignore = "subprocess helper launched only by the AppContainer script test"]
    fn appcontainer_script_probe_helper() {
        assert!(process_is_appcontainer());
        let script = PathBuf::from(std::env::var_os(PROBE_SCRIPT_PATH).expect("script path"));
        let script_matches = std::fs::read(script)
            .expect("private script is readable only inside its profile")
            == b"fixture-script-secret";
        assert!(script_matches, "private script payload diverged");
        assert!(std::env::var_os("PALLADIN_API_KEY").is_none());
    }

    #[test]
    #[ignore = "subprocess helper launched only by the AppContainer tree test"]
    #[allow(clippy::zombie_processes)] // Windows has no Unix zombie state; the Job must outlive this root.
    fn appcontainer_tree_root_helper() {
        assert!(process_is_appcontainer());
        std::process::Command::new(std::env::current_exe().expect("probe executable"))
            .args([
                "--exact",
                "windows::tests::appcontainer_tree_descendant_helper",
                "--ignored",
            ])
            .spawn()
            .expect("tree descendant");
    }

    #[test]
    #[ignore = "subprocess helper launched only by the AppContainer tree test"]
    fn appcontainer_tree_descendant_helper() {
        assert!(process_is_appcontainer());
        std::thread::sleep(std::time::Duration::from_secs(1));
        let survivor =
            PathBuf::from(std::env::var_os(PROBE_SURVIVOR_PATH).expect("survivor marker path"));
        std::fs::write(survivor, b"survived").expect("survivor marker");
    }

    fn process_is_appcontainer() -> bool {
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).expect("process token");
        }
        let token = unsafe { owned_handle(token).expect("owned process token") };
        let mut is_appcontainer = 0_u32;
        let mut returned = 0_u32;
        unsafe {
            GetTokenInformation(
                raw_handle(&token),
                TokenIsAppContainer,
                Some((&raw mut is_appcontainer).cast()),
                u32::try_from(size_of::<u32>()).expect("token flag size"),
                &mut returned,
            )
            .expect("AppContainer token information");
        }
        returned == u32::try_from(size_of::<u32>()).expect("token flag size")
            && is_appcontainer == 1
    }

    #[test]
    fn pinned_executable_prevents_parent_path_replacement_until_drop() {
        let root = tempfile::tempdir().expect("temporary root");
        let original = root.path().join("original");
        let replacement = root.path().join("replacement");
        std::fs::create_dir(&original).expect("original directory");
        let executable = original.join("fixture.exe");
        std::fs::write(&executable, b"fixture").expect("fixture executable");

        let pinned = PinnedExecutable::pin(executable).expect("pinned executable");
        assert!(
            std::fs::rename(&original, &replacement).is_err(),
            "a pinned executable parent was replaced"
        );
        drop(pinned);
        std::fs::rename(&original, &replacement).expect("rename after pin release");
    }
}
