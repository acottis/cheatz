use winapi::shared::minwindef::*;
use winapi::um::winuser::{MessageBoxW, MB_OK, MB_ICONINFORMATION};

#[no_mangle]
pub extern "system" fn DllMain(hinst: HINSTANCE, reason: DWORD, reserved: LPVOID) -> BOOL {
    println!("Hello from the library!");


    DllTest();

    TRUE
}

#[no_mangle]
pub extern fn DllTest(){
    println!("Hello from the library!"); 

    let l_msg: Vec<u16> = "Wassa wassa wassup\0".encode_utf16().collect();
    let l_title: Vec<u16> = "\u{20BF}itconnect\0".encode_utf16().collect();

    unsafe {
        MessageBoxW(std::ptr::null_mut(), l_msg.as_ptr(), l_title.as_ptr(), MB_OK | MB_ICONINFORMATION);
    }
}