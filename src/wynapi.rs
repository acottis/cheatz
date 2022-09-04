//! This file does the raw windows function calls and puts a rust wrapper ontop
//! to abstract away the unsafe usage and windows types

use anyhow::Result;
use core::ffi::c_void;
use core::mem::size_of;
use std::os::windows::io::HandleOrNull;

type DWORD = i32;
type HANDLE = *mut c_void;
type LPVOID = *mut c_void;
type LPCVOID = *const c_void;
type HMODULE = HANDLE;
type FARPROC = *const c_void;
type LPCSTR = *const i8;

pub mod flags {
    pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    pub const PROCESS_VM_READ: u32 = 0x0010;
    pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
    pub const PROCESS_VM_WRITE: u32 = 0x0020;
    pub const PROCESS_VM_OPERATION: u32 = 0x0008;

    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_RELEASE: u32 = 0x8000;

    pub const PAGE_READWRITE: u32 = 0x0004;
}

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

#[allow(dead_code)]
#[link(name = "Kernel32")]
extern "system" {
    fn GetLastError() -> DWORD;
    /// https://docs.microsoft.com/en-us/windows/win32/api/Psapi/nf-psapi-enumprocesses
    fn K32EnumProcesses(
        lpidProcess: *mut u32,
        cb: DWORD,
        lpcbNeeded: &mut DWORD,
    ) -> bool;
    /// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
    fn OpenProcess(
        dwDesiredAccess: u32,
        bInheritHandle: bool,
        dwProcessId: u32,
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
    /// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const i8) -> FARPROC;
    /// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
    fn GetModuleHandleA(lpModuleName: LPCSTR) -> HMODULE;
    /// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    fn VirtualAllocEx(
        hProcess: HANDLE,
        lpAddress: LPVOID,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> LPVOID;
    /// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    fn WriteProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: LPVOID,
        lpBuffer: LPCVOID,
        nSize: usize,
        lpNumberOfBytesWritten: &mut usize,
    ) -> bool;
    /// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
    fn CreateRemoteThread(
        hProcess: HANDLE,
        lpThreadAttributes: *const u8,
        dwStackSize: usize,
        lpStartAddress: LPCVOID,
        lpParameter: LPCVOID,
        dwCreationFlags: u32,
        lpThreadId: &mut u32,
    ) -> HANDLE;
    /// https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: u32) -> u32;
}

/// Rust wrapper around [K32EnumProcesses], we return all pids
pub fn enum_processes() -> Result<Vec<u32>> {
    let mut processes: [u32; 1024] = [0u32; 1024];
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
pub fn open_process(pid: u32, permissions: u32) -> Option<HANDLE> {
    let handle = unsafe { OpenProcess(permissions, false, pid) };
    if handle.is_null() {
        return None;
    }
    Some(handle)
}
/// Rust wrapper around [CloseHandle], takes a [HANDLE] returns a [bool]
#[inline(always)]
pub fn close_handle(handle: HANDLE) -> Result<()> {
    let succeeded = unsafe { CloseHandle(handle) };
    if !succeeded {
        return Err(Error::get_last().into());
    }
    Ok(())
}
/// Rust wrapper around [K32GetModuleBaseNameA]
#[inline(always)]
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
pub fn _enum_process_modules(handle: HANDLE) -> Result<Vec<HMODULE>> {
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
/// Rust wrapper around [GetProcAddress]
pub fn get_proc_address(
    module_name: &str,
    target: &str,
) -> Result<*const c_void> {
    let c_module_name = std::ffi::CString::new(module_name)?;
    let c_target = std::ffi::CString::new(target)?;

    let hm = unsafe { GetModuleHandleA(c_module_name.as_ptr()) };
    if hm.is_null() {
        return Err(Error::get_last().into());
    }

    let addr = unsafe { GetProcAddress(hm, c_target.as_ptr()) };
    if addr.is_null() {
        return Err(Error::get_last().into());
    }

    Ok(addr)
}
/// Rust wrapper around [VirtualAllocEx]
pub fn virtual_alloc_ex(
    process_handle: HANDLE,
    alloc_size: usize,
    alloc_type: u32,
    protection: u32,
) -> Result<LPVOID> {
    let alloc_base_addr = unsafe {
        VirtualAllocEx(
            process_handle,
            core::ptr::null_mut(),
            alloc_size,
            alloc_type,
            protection,
        )
    };
    if alloc_base_addr.is_null() {
        return Err(Error::get_last().into());
    }
    Ok(alloc_base_addr)
}
/// Rust wrapper around [WriteProcessMemory]
pub fn write_process_memory(
    process_handle: HANDLE,
    alloc_base_addr: LPVOID,
    buf: *const u8,
    buf_size: usize,
) -> Result<usize> {
    let mut bytes_written = 0;

    let succeeded = unsafe {
        WriteProcessMemory(
            process_handle,
            alloc_base_addr,
            buf as LPCVOID,
            buf_size,
            &mut bytes_written,
        )
    };
    if !succeeded {
        return Err(Error::get_last().into());
    }
    Ok(bytes_written)
}
/// Rust wrapper around [CreateRemoteThread]
pub fn create_remote_thread(
    process_handle: HANDLE,
    fn_to_call: *const u8,
    fn_param: *const u8,
) -> Result<(HANDLE, u32)> {
    let mut thread_id = 0;
    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle,
            core::ptr::null(),
            0,
            fn_to_call as LPCVOID,
            fn_param as LPCVOID,
            0,
            &mut thread_id,
        )
    };
    if thread_handle.is_null() {
        return Err(Error::get_last().into());
    }
    Ok((thread_handle, thread_id))
}
/// Rust wrapper around [WaitForSingleObject]
pub fn wait_for_single_object(handle: HANDLE, milliseconds: u32) -> Result<()> {
    let status = unsafe { WaitForSingleObject(handle, milliseconds) };
    if status != 0 {
        anyhow::bail!(
            "Object never reached signaled state after {milliseconds} miliseconds"
        )
    }
    Ok(())
}
