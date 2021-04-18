use winapi::um::winuser::{MessageBoxW, MB_OK, MB_ICONINFORMATION};

#[no_mangle]
pub extern "system" fn DllMain(hinst: *mut usize, reason: Reason, _reserved: usize) -> bool {

    let BASE_ADDR = hinst;

    println!("{:?},{:?}", BASE_ADDR, reason);

    match reason {
        Reason::DllProcessAttach => on_dll_attach(),
        Reason::DllProcessDetach => on_dll_detach(),
        Reason::DllThreadAttach => on_thread_attach(),
        Reason::DllThreadDetach => on_thread_detach(),
    }

    true
}

pub extern fn on_dll_attach(){
    println!("Process Attched");
    pop_up();
}

pub extern fn on_dll_detach(){
    println!("Process Detched");
}

pub extern fn on_thread_attach(){
    println!("Thread Attched");
}

pub extern fn on_thread_detach(){
    println!("Thread Detched");
}

#[no_mangle]
pub extern fn pop_up(){

    let l_msg: Vec<u16> = "Injected into your veinzzz\0".encode_utf16().collect();
    let l_title: Vec<u16> = "Hacked\0".encode_utf16().collect();

    unsafe {
        MessageBoxW(std::ptr::null_mut(), l_msg.as_ptr(), l_title.as_ptr(), MB_OK | MB_ICONINFORMATION);
    }
}

#[derive(Debug)]
#[repr(u32)]
pub enum Reason{
    DllProcessDetach = 0,
    DllProcessAttach = 1,
    DllThreadAttach = 2,
    DllThreadDetach = 3,
}