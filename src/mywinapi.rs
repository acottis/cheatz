#![allow(dead_code)]

use anyhow::Result;
use core::mem::size_of;

type DWORD = i32;
type WORD = i16;
type UINT = u32;
type WPARAM = *const i32;
type HANDLE = *mut core::ffi::c_void;
type HWND = HANDLE;
type HMODULE = HANDLE;

const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
const PROCESS_VM_READ: DWORD = 0x0010;

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum Error {
    PROC_NOT_FOUND,
    NOACCESS,
    INVALID_PARAMETER,
    NOT_SUPPORTED,
    INVALID_HANDLE,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // let msg: &str = match self {
        //     Self::PROC_NOT_FOUND => { "\x1b[1;31mLastError: Proc Not
        // Found\x1b[1;0m" }     Self::NOACCESS => {
        // "\x1b[1;31mLastError: No Access\x1b[1;0m" }
        //     Self::INVALID_PARAMETER => { "\x1b[1;31mLastError: \x1b[1;0m" }
        // };
        core::fmt::write(f, format_args!("{:?}", self))
    }
}

impl std::error::Error for self::Error {}

impl Error {
    /// Rust wrapper around GetLastError()
    pub fn get_last() -> Self {
        let err = unsafe { GetLastError() };
        match err {
            5 => Self::NOT_SUPPORTED,
            6 => Self::INVALID_HANDLE,
            87 => Self::INVALID_PARAMETER,
            127 => Self::PROC_NOT_FOUND,
            998 => Self::NOACCESS,
            _ => unimplemented!("GetLastError code: {err} not yet handled"),
        }
    }
}

#[link(name = "Kernel32")]
extern "system" {
    fn GetLastError() -> DWORD;
    /// https://docs.microsoft.com/en-us/windows/win32/api/Psapi/nf-psapi-enumprocesses
    fn K32EnumProcesses(
        lpidProcess: *mut DWORD,
        cb: DWORD,
        lpcbNeeded: &mut DWORD,
    ) -> bool;
    /// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
    fn OpenProcess(
        dwDesiredAccess: DWORD,
        bInheritHandle: bool,
        dwProcessId: DWORD,
    ) -> HANDLE;
    /// https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
    fn CloseHandle(hObject: HANDLE) -> bool;
    /// https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulebasenamea
    fn K32GetModuleBaseNameA(
        hProcess: HANDLE,
        hModule: HMODULE,
        lpBaseName: *mut u8,
        nSize: DWORD,
    ) -> DWORD;
    /// https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules
    fn K32EnumProcessModules(
        hProcess: HANDLE,
        lphModule: *mut HMODULE,
        cb: DWORD,
        lpcbNeeded: *mut DWORD,
    ) -> bool;
}

/// Rust wrapper around [K32EnumProcesses], we return all pids
pub fn enum_processes() -> Result<Vec<i32>> {
    let mut processes: [DWORD; 1024] = [0i32; 1024];
    let cb: DWORD = (processes.len() * size_of::<DWORD>()) as DWORD;
    let mut process_count_as_bytes: DWORD = 0;
    let succeeded = unsafe {
        K32EnumProcesses(
            processes.as_mut_ptr(),
            cb,
            &mut process_count_as_bytes,
        )
    };
    if !succeeded {
        return Err(Error::get_last().into());
    }
    // The number of bytes, but each byte is part of a DWORD (u32) so we divide
    // by the size
    let process_count = process_count_as_bytes / (size_of::<DWORD>() as i32);

    Ok(processes[..process_count as usize].to_vec())
}

/// Rust wrapper around [OpenProcess], takes a pid returns a [HANDLE]
pub fn open_process(pid: i32) -> Option<HANDLE> {
    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
    };
    if handle.is_null() {
        return None;
    }

    Some(handle)
}
/// Rust wrapper around [CloseHandle], takes a [HANDLE] returns a [bool]
pub fn close_handle(handle: HANDLE) -> Result<()> {
    let succeeded = unsafe { CloseHandle(handle) };
    if !succeeded {
        return Err(Error::get_last().into());
    }
    Ok(())
}
/// Rust wrapper around [K32GetModuleBaseNameA]
pub fn get_module_base_name_a(
    handle: HANDLE,
    module_handle: HANDLE,
) -> Result<String> {
    const BUF_SIZE: DWORD = 100;
    let mut name = [0u8; BUF_SIZE as usize];
    let len = unsafe {
        K32GetModuleBaseNameA(
            handle,
            module_handle,
            name.as_mut_ptr(),
            BUF_SIZE,
        )
    };
    if len == 0 {
        return Err(Error::get_last().into());
    }
    Ok(String::from_utf8(name[..len as usize].to_vec())?)
}
/// Rust wrapper around [K32EnumProcessModules]
pub fn enum_process_modules(handle: HANDLE) -> Result<Vec<HMODULE>> {
    const BUF_SIZE: usize = 500;

    let cb = BUF_SIZE * size_of::<HMODULE>();
    let mut modules_count_as_bytes = 0;
    let mut modules = [core::ptr::null_mut(); BUF_SIZE];
    let succeeded = unsafe {
        K32EnumProcessModules(
            handle,
            modules.as_mut_ptr(),
            cb as i32,
            &mut modules_count_as_bytes,
        )
    };
    if !succeeded {
        return Err(Error::get_last().into());
    }
    let module_count = modules_count_as_bytes / (size_of::<HMODULE>() as i32);

    Ok(modules[..module_count as usize].to_vec())
}
