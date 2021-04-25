use winapi::um::processthreadsapi::CreateThread;
use winapi::um::consoleapi::AllocConsole;
use winapi::um::winuser::GetAsyncKeyState;

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
            core::ptr::null_mut(),
            0, 
            core::mem::transmute(cheat_main as *const ()), 
            core::mem::transmute(hinst), 
            0, 
            core::ptr::null_mut()
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

    let kc_reverse = &mut MemoryHack::new(0x253C25,b"\x29");

    loop{
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        if key_down(Key::F5){
            println!("F5 is pressed");
            kc_reverse.patch_bytes();
        }
        if key_down(Key::F6){
            println!("F6 is pressed");
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

#[repr(i32)]
#[allow(dead_code)]
enum Key{
    F5 = 0x74,
    F6 = 0x75,
    ESC = 0x1B,
}