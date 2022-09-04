//! Must be compiled with stable-i686-pc-windows-msvc as the game is 32 bit
//! Currently will only work in debug compile by default as that is where the dll is generated
//! ### Todo
//! - Speedhack
//! - AimBot
//! - ~~Split into two crates~~
//! - Better error handling on opening game (Half done)
//! - Improve user input of the DLL path and process name
//! - Implement a check for the expected memory state before injecting the cheat
//! - Write Code Cave for an exisiting easy hack
//! - Hook a process

use winapi::um::handleapi::CloseHandle;
#[warn(missing_docs)]
use winapi::um::memoryapi::{
    VirtualFreeEx, WriteProcessMemory,
};
use winapi::um::processthreadsapi::CreateRemoteThread;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use anyhow::{bail, Result};

use crate::wynapi::virtual_alloc_ex;

mod wynapi;
/// Entry Point, here two variables currently need changed by the user. "dll" and "PROCESS" the dll is the path to the dll we want to inject and PROCESS is the string that the process id we are searching for contains
///
fn main() {
    // Take the first command line Arg or defult to injecting notepad.exe
    let target: String =
        std::env::args().nth(1).unwrap_or("notepad.exe".to_owned());

    let dll = "target/debug/deps/cheatlib.dll";

    inject(&target, dll);
}
/// Find the Process id from a &[str]
/// Caveat: it returns the first PID it finds, even if their are multiple
fn get_pid_from_name(process_name: &str) -> Result<u32> {
    // Gets all running processes
    let pids = wynapi::enum_processes()?;
    let process_name = process_name.to_lowercase();
    for pid in &pids {
        // Open each proccess from its PID
        let handle = wynapi::open_process(
            *pid,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        );
        if let Some(h) = handle {
            // Get the module handle (Unneeded?)
            // let mh = wynapi::enum_process_modules(h)?;
            // Get the process name
            let module_name =
                wynapi::get_module_base_name_a(h, core::ptr::null_mut())?
                    .to_lowercase();
            // Close the handle once we are done
            wynapi::close_handle(h)?;
            if module_name == process_name {
                return Ok(*pid as u32);
            }
        }
    }
    bail!("Could not find process with name `{process_name}`")
}
///Injects the DLL generated by cheat lib into the process ID found
///
fn inject(process_name: &str, dll: &str) {
    let pid = get_pid_from_name(&process_name).unwrap();

    // Get the address of the LoadLibaryA Function
    let loadlib_addr =
        wynapi::get_proc_address("kernelbase.dll", "LoadLibraryA").unwrap();

    // !!!!!!!!!!!!!!Fix this after!!!!!!!!!!!!!!!!!!!!!!!!!!!
    let full_path: String = std::fs::canonicalize(dll)
        .expect("DLL not found")
        .to_str()
        .unwrap()
        .replace("\\\\?\\", "");
    let path_size: usize = full_path.len();
    println!("{}, Len: {}", full_path, path_size);

    // Open the target application with permissions to create the DLL and write memory
    let p_handle = if let Some(handle) = wynapi::open_process(
        pid,
        PROCESS_CREATE_THREAD
            | PROCESS_VM_WRITE
            | PROCESS_VM_OPERATION
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_READ,
    ) {
        handle
    } else {
        panic!("Could not open process");
    };

    // Get base address of target process
    let alloc_base_addr = virtual_alloc_ex(
        p_handle,
        50,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ).unwrap();

    let mut bytes_written_to_process = 0;

    unsafe {
        assert!(
            WriteProcessMemory(
                core::mem::transmute(p_handle),
                core::mem::transmute(alloc_base_addr),
                core::mem::transmute(full_path.as_ptr()),
                path_size,
                &mut bytes_written_to_process
            ) != 0,
            "Could not write to process"
        )
    };

    println!("Wrote {} bytes", bytes_written_to_process);

    let handle_thread = unsafe {
        CreateRemoteThread(
            core::mem::transmute(p_handle),
            core::ptr::null_mut(),
            0,
            core::mem::transmute(loadlib_addr),
            core::mem::transmute(alloc_base_addr),
            0,
            core::ptr::null_mut(),
        )
    };
    assert!(
        !handle_thread.is_null(),
        "Could not create thread in remote process"
    );
    println!("Thread Handle: {:?}", handle_thread);

    let status = unsafe { WaitForSingleObject(handle_thread, 0xFFFFFFFF) };

    println!("Wait Status: {:X}", status);

    unsafe {
        assert!(
            CloseHandle(handle_thread) != 0,
            "Thread handle failed to close sucessfully"
        )
    };

    unsafe {
        VirtualFreeEx(
            core::mem::transmute(p_handle),
            core::mem::transmute(full_path.as_ptr()),
            0,
            MEM_RELEASE,
        )
    };

    unsafe {
        assert!(
            CloseHandle(core::mem::transmute(p_handle)) != 0,
            "Process Handle failed to close sucessfully"
        )
    };
}
