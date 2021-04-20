use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread };
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::{PROCESS_CREATE_THREAD, PROCESS_VM_WRITE, PROCESS_VM_OPERATION, MEM_COMMIT, PAGE_READWRITE};
use winapi::ctypes::c_void;


use std::process::Command;

fn main() {

    let dll = "target/debug/cheatlib.dll";
    let process = "note";
    
    inject(process, dll);
}

// Uses powershell to find 
fn get_process_id(process: &str) -> Option<(String, u32)>{

    let out_raw = {
        Command::new("powershell.exe")
            .args(&[format!("get-process | Where ProcessName -like \"{}*\" | foreach {{Write-Host \"$($_.ProcessName),$($_.id),$($_.Path)\"}}", process)])
            .output()
            .expect("Failed to execute command")
    };

    let out_str = std::str::from_utf8(&out_raw.stdout).expect("Failed to convert pid");

    for line in out_str.lines(){

        let out_split: Vec<&str> = line.split(",").collect();

        let exename: String = out_split[0].to_string();
        let pid:u32 = out_split[1].parse().expect("PID not a number");

        return Some((exename, pid))
    }
    None
}


fn inject(process: &str, dll: &str){

    let process_info = get_process_id(process).expect("No process with that name active");
    println!("Process: {}, PID: {}", process_info.0, process_info.1);
  
    let loadlib_addr = unsafe {
        GetProcAddress(
        LoadLibraryA("kernelbase.dll\0".as_ptr() as *const i8),
        "LoadLibraryA\0".as_ptr() as *const i8) as *const i8
    };
    println!("LoadLibrary at: {:#X?}", loadlib_addr);


    let full_path = std::fs::canonicalize(dll).expect("DLL not found").to_str().unwrap().replace("\\\\?\\", "");
    let path_size = full_path.len() as usize + 1;
    println!("{:?}, Len: {}", full_path, path_size);

    // Open the target application with permissions to create the DLL and write memory
    let handle_process = unsafe{
        OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION,
        0,
        process_info.1)
    };
    assert!(handle_process != std::ptr::null_mut(), "Process Handle is null");
    println!("Process Handle: {:?}", handle_process);

    let my_base_address = unsafe{
        VirtualAllocEx(handle_process,
            std::ptr::null_mut(), 
            path_size, 
            MEM_COMMIT, 
            PAGE_READWRITE)};
    println!("Allocation Base: {:?}", my_base_address);
    assert!(!my_base_address.is_null(), "Allocation failed");
    
    let mut n = 0;

    unsafe {assert!(WriteProcessMemory(handle_process,
        my_base_address,
        full_path.as_ptr() as *const c_void, 
        path_size, 
        &mut n) != 0, "Could not write to process") };

    println!("Wrote {} bytes", n);

    let handle_thread = unsafe {
        CreateRemoteThread(handle_process,
            std::ptr::null_mut(), 
            0, 
            std::mem::transmute(loadlib_addr), 
            my_base_address, 
            0, 
            std::ptr::null_mut())
    };
    println!("Thread Handle: {:?}", handle_thread);

    unsafe {WaitForSingleObject(handle_process, 0)};

    unsafe {assert!(CloseHandle(handle_thread) != 0, "Thread handle failed to close sucessfully")};
    unsafe {assert!(CloseHandle(handle_process) != 0, "Process Handle failed to close sucessfully")};

}