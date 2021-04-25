use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::memoryapi::{ReadProcessMemory,WriteProcessMemory};

// const PATCH_SIZE: u8 = 2;

// pub struct MemoryHack {
//     patch_address: usize,
//     patch_bytes: [u8; PATCH_SIZE],
//     original_bytes: [u8; PATCH_SIZE],
// }

// impl MemoryHack{

//     fn bytes();

// }


// Exchange bytes and store old at target offset
pub fn bytes(off_addr:usize, new_bytes: [u8;10], old_bytes: [u8;10]){
    // Get base address

    let base_addr = unsafe {
        GetModuleHandleA(std::ptr::null_mut()) as *const usize
    };

    // Read bytes and return success or failure
    let read_result  = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            std::mem::transmute(base_addr as usize + off_addr),
                    std::mem::transmute(old_bytes.as_ptr()),
                    1, 
                    std::ptr::null_mut())
    };
    println!("Result of memory read: {}, with data: {:X?}", read_result, old_bytes);

    // Write bytes and return success or failure
    let write_result = unsafe { WriteProcessMemory(
        GetCurrentProcess(),
        std::mem::transmute(base_addr as usize + off_addr),
        core::mem::transmute(new_bytes.as_ptr()),
        1, 
        std::ptr::null_mut())};
    println!("Result of memory write: {}", write_result);


}


