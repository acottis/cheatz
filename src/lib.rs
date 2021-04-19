use winapi::um::winuser::{MessageBoxW, MB_OK, MB_ICONINFORMATION};
use winapi::um::processthreadsapi::CreateThread;
use winapi::um::consoleapi::AllocConsole;
// use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::ctypes::c_void;

use std::fs::OpenOptions;
use std::io::prelude::*;

#[no_mangle]
pub extern "system" fn DllMain(hinst: *mut usize, reason: Reason, _reserved: usize) -> bool {

    let BASE_ADDR = hinst;

    println!("{:?},{:?}", BASE_ADDR, reason);

    
    match reason {
        Reason::DllProcessAttach => on_dll_attach(hinst),
        Reason::DllProcessDetach => on_dll_detach(),
        Reason::DllThreadAttach => on_thread_attach(),
        Reason::DllThreadDetach => on_thread_detach(),
    }

    true
}

extern fn on_dll_attach(hinst: *mut usize){
    println!("Process Attached");
    //cheat();

    unsafe { AllocConsole()};
    // let test = SECURITY_ATTRIBUTES {
    //     nLength: 0,
    //     lpSecurityDescriptor: std::ptr::null_mut(),
    //     bInheritHandle: 0,
    // };

    let x = unsafe { 
        CreateThread(
            std::ptr::null_mut(),
            0, 
            std::mem::transmute(cheat as *const ()), 
            hinst as *mut c_void, 
            0, 
            std::ptr::null_mut()
        )};

        println!("Created Thread in DLL: {:?}", x);

    //pop_up();
    //log().unwrap();
}

extern fn on_dll_detach(){
    println!("Process Detached");
}

extern fn on_thread_attach(){
    println!("Thread Attached");
    
}

extern fn on_thread_detach(){
    println!("Thread Detached");
}

fn cheat(hinst: *mut usize){

    let test = "testing";
    
    for x in 1..2 {
        log(test).unwrap();
        pop_up();
        println!("hello");
    }
}

fn pop_up(){

    let l_msg: Vec<u16> = "Injected into your veinzzz\0".encode_utf16().collect();
    let l_title: Vec<u16> = "Hacked\0".encode_utf16().collect();

    unsafe {
        MessageBoxW(std::ptr::null_mut(), l_msg.as_ptr(), l_title.as_ptr(), MB_OK | MB_ICONINFORMATION);
    }
}

fn log(msg: &str) -> std::io::Result<()>{
    
    let mut file = OpenOptions::new()
    .write(true)
    .append(true)
    .create(true)
    .open("C:\\temp\\cheatz.log")?;

    writeln!(file, "{}", msg)?;

    Ok(())
}

#[derive(Debug)]
#[repr(u32)]
pub enum Reason{
    DllProcessDetach = 0,
    DllProcessAttach = 1,
    DllThreadAttach = 2,
    DllThreadDetach = 3,
}