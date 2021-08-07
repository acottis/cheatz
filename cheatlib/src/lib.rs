//! Must be compiled with stable-i686-pc-windows-msvc as the game is 32 bit
//! This is a generic patcher that updates a memory address of a live process when a key is pressed//! 
//! 
//! ### Memory Addresses:
//! - BattlefrontII.exe+0x253C25 -> b"\x29" (Reverse the kill count on kill)
//! - BattlefrontII.exe+0x8908E -> b"\x90\x90\x90\x90\x90" (Turns off all damage)
//! - BattlefrontII.exe+0x8908E -> b"\xF3\x0F\x58\xC2" (Reverse Damage)
//! 
//! ### Current Cheats (BattlefrontII.exe)
//! ```rust
//!     let kc_reverse = &mut MemoryHack::new(0x253C25, b"\x29");
//!     let dmg_off = &mut MemoryHack::new(0x8908E, b"\x90\x90\x90\x90\x90");
//!     let dmg_reverse = &mut MemoryHack::new(0x89081, b"\xF3\x0F\x58\xC2"); 
//! ```

#[warn(missing_docs)]

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

    let thread_handle = unsafe { 
        CreateThread(
            core::ptr::null_mut(),
            0, 
            core::mem::transmute(cheat_main as *const ()), 
            core::mem::transmute(hinst), 
            0, 
            core::ptr::null_mut()
        )};

    println!("Created Thread in DLL: {:?}", thread_handle);

}
extern fn on_dll_detach(){
    println!("Process Detached");
    unsafe { winapi::um::wincon::FreeConsole(); }
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


    let mut hacks = [
        &mut MemoryHack::new(0x253C25, b"\x29"), // KC_REVERSE
        &mut MemoryHack::new(0x8908E, b"\x90\x90\x90\x90\x90"), // DMG_OFF
        &mut MemoryHack::new(0x89081, b"\xF3\x0F\x58\xC2") // DMG_REVERSE
    ];
    // let kc_reverse = &mut MemoryHack::new(0x253C25, b"\x29");
    // let dmg_off = &mut MemoryHack::new(0x8908E, b"\x90\x90\x90\x90\x90");
    // let dmg_reverse = &mut MemoryHack::new(0x89081, b"\xF3\x0F\x58\xC2"); 

    loop{
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        if key_down(Key::F5){
            println!("F5 is pressed");
            //dmg_reverse.patch_bytes();
            //dmg_reverse.patch_bytes();
            hacks[2].patch_bytes();
        }
        if key_down(Key::F6){
            println!("F6 is pressed");
            hacks[2].unpatch_bytes();
           // kc_reverse.unpatch_bytes();
        }
        // When ESC is pressed we unpatch all cheats and unload the DLL which triggers a process unload
        if key_down(Key::ESC){
            // Remove all active patches
            for hack in hacks.iter_mut(){
                hack.unpatch_bytes();
            }
            // Unload the library
            unsafe {
                winapi::um::libloaderapi::FreeLibraryAndExitThread(
                    core::mem::transmute(hinst),
                    0
                )
            }
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