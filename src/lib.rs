//use winapi::um::winuser::{MessageBoxW, MB_OK, MB_ICONINFORMATION};
use winapi::um::processthreadsapi::{CreateThread, GetCurrentProcess};
use winapi::um::consoleapi::AllocConsole;
use winapi::ctypes::c_void;
use winapi::um::winuser::{GetAsyncKeyState, WM_KEYDOWN};
use winapi::um::libloaderapi::GetModuleHandleA;

use std::fs::OpenOptions;
use std::io::prelude::*;

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
    println!("Key {:?}", Key::F5);

    let base_addr = unsafe {
        GetModuleHandleA(std::ptr::null_mut()) as *const usize
    };

    let target_off = 0x253C25;

    let target_addr = base_addr as usize + target_off;

    let x = unsafe {std::ptr::read(base_addr)};

    println!("Content at base address: {:X}", x as u8);

    println!("size: {}", core::mem::size_of::<*const usize>());

    println!("base addr {:X}", base_addr as usize);
    println!("target addr {:X}", target_addr);

    //let y = unsafe{ base_addr.offset(target/4)};

    //println!("Address to modify: {:?}", y);

    //let test = unsafe {base_addr.offset(target)};

    let mut target = unsafe {std::ptr::read(target_addr as *const usize)};


    println!("Content to modify {:X?}", target as u8);
    println!("test: {:X?}", target_addr as *mut usize);

    //unsafe { std::ptr::write_bytes(target_addr as *mut usize, 0x29, 1) };
    
    // let read = unsafe {
    //     std::ptr::read(target)
    // };

    // println!("At target: {:X}", read);

    loop{

        std::thread::sleep(std::time::Duration::from_millis(10));
        let key_press: KeyPress = unsafe {KeyPress::read(GetAsyncKeyState(Key::F5.code()))};
        match key_press {
            KeyPress::WasDown => println!("Detected Key: {:?}", key_press),
            KeyPress::Down => println!("Detected Key: {:?}", key_press),
            _ => ()// println!("Reported other, {:?}", key_press),
        }

        
        let esc_press: KeyPress = unsafe {KeyPress::read(GetAsyncKeyState(Key::ESC.code()))};
        match esc_press {
            KeyPress::WasDown => println!("Detected Key: {:?}", esc_press),
            KeyPress::Down => break,
            _ => ()// println!("Reported other, {:?}", key_press),
        }

    };

}

// fn pop_up(){

//     let l_msg: Vec<u16> = "Injected into your veinzzz\0".encode_utf16().collect();
//     let l_title: Vec<u16> = "Hacked\0".encode_utf16().collect();

//     unsafe {
//         MessageBoxW(std::ptr::null_mut(), l_msg.as_ptr(), l_title.as_ptr(), MB_OK | MB_ICONINFORMATION);
//     }
// }

fn log(msg: String) -> std::io::Result<()>{
    
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
#[derive(Debug, PartialEq, Eq)]
#[repr(u32)]
enum KeyPress{
    Down,
    WasDown,
    Other,
}

impl KeyPress{
    fn read(state: i16) -> KeyPress{
        match state as u16 {
            0x8000 => KeyPress::Down,
            0x8001 => KeyPress::WasDown,
            _ => KeyPress::Other,
        }
    }
}

#[derive(Debug)]
#[repr(i32)]
enum Key{
    F5 = 0x74,
    ESC = 0x1B,
}

impl Key{
    fn code(&self) -> i32{
        match self {
            Key::F5 => 0x74,
            Key::ESC => 0x1B,
            _ => 0
        }
    }
}