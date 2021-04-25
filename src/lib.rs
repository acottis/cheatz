//use winapi::um::winuser::{MessageBoxW, MB_OK, MB_ICONINFORMATION};
use winapi::um::processthreadsapi::{CreateThread};
use winapi::um::consoleapi::AllocConsole;
use winapi::ctypes::c_void;
use winapi::um::winuser::{GetAsyncKeyState, WM_KEYDOWN};

use std::fs::OpenOptions;
use std::io::prelude::*;

mod patch;
use patch::MemoryHack;


#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn DllMain(hinst: *mut usize, reason: Reason, _reserved: usize) -> bool {

    match reason {
        Reason::DllProcessAttach => on_dll_attach(hinst),
        Reason::DllProcessDetach => on_dll_detach(),
        Reason::DllThreadAttach => on_thread_attach(),
        Reason::DllThreadDetach => on_thread_detach(),
    }

    true
}

extern fn on_dll_attach(hinst: *mut usize){

    unsafe {AllocConsole()};
    println!("cheatDll Base Address: {:?}", hinst); 

    let x = unsafe { 
        CreateThread(
            std::ptr::null_mut(),
            0, 
            std::mem::transmute(cheat_main as *const ()), 
            hinst as *mut c_void, 
            0, 
            std::ptr::null_mut()
        )};

    println!("Created Thread in DLL: {:?}", x);

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

// Main cheat loop
fn cheat_main(hinst: *mut usize){

    println!("Process Attached, base address: {:?}", hinst);

    let kc_reverse_vals = (0x253C25, &mut [0x29u8;1], &mut [0u8; 1]);
    let kc_reverse = &mut MemoryHack::new(kc_reverse_vals.0,kc_reverse_vals.1, kc_reverse_vals.2);


    loop{
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        if key_down(Key::F5){
            println!("F5 is down");
            kc_reverse.patch_bytes();
        }
        if key_down(Key::F6){
            println!("F6 is down");
            kc_reverse.unpatch_bytes();
        }
    };
}

fn key_down(key: Key) -> bool {
    unsafe{
        if GetAsyncKeyState(key as i32) as u16 == 0x8001{
            return true
        }
    }
    false
}

fn _log_to_disk(msg: String) -> std::io::Result<()>{
    
    let mut file = OpenOptions::new()
    .write(true)
    .append(true)
    .create(true)
    .open("C:\\temp\\cheatz.log")?;

    writeln!(file, "{}", msg)?;

    Ok(())
}
#[allow(dead_code)]
#[derive(Debug)]
#[repr(u32)]
pub enum Reason{
    DllProcessDetach = 0,
    DllProcessAttach = 1,
    DllThreadAttach = 2,
    DllThreadDetach = 3,
}

#[derive(Debug)]
#[repr(i32)]
#[allow(dead_code)]
enum Key{
    F5 = 0x74,
    F6 = 0x75,
    ESC = 0x1B,
}