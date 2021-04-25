use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::memoryapi::{ReadProcessMemory,WriteProcessMemory};

pub struct MemoryHack<'a> {
    pub off_addr: usize,
    pub new_bytes: &'a[u8],
    pub old_bytes: &'a mut [u8],
    enabled: bool,
}

impl<'a> MemoryHack<'a>{

    pub fn new(off_addr:usize, new_bytes:  &'a[u8], old_bytes: &'a mut [u8]) -> Self{

        MemoryHack {
            off_addr: off_addr,
            new_bytes: new_bytes,
            old_bytes: old_bytes,
            enabled: false,
        }
    }

    pub fn patch_bytes(&self){

        println!("new bytes: {:X?}", self.new_bytes);

        // Get base address of program
        let base_addr = unsafe {
            GetModuleHandleA(core::ptr::null_mut()) as usize
        };
    
        // Write bytes and return success or failure
        let write_result = unsafe { WriteProcessMemory(
            GetCurrentProcess(),
            core::mem::transmute(base_addr + self.off_addr),
            core::mem::transmute(self.new_bytes.as_ptr()),
            1, 
            core::ptr::null_mut())};
        println!("Result of memory write: {}", write_result);
    
        // Read bytes and return success or failure
        let read_result  = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                core::mem::transmute(base_addr as usize + self.off_addr),
                core::mem::transmute(self.old_bytes.as_ptr()),
                1, 
                core::ptr::null_mut())
        };
        println!("Result of memory read: {}, with data: {:X?}", read_result, self.old_bytes);

    }

}


// Exchange bytes and store old at target offset
pub fn bytes(off_addr:usize, new_bytes: &[u8], old_bytes: &mut [u8]){
    
    println!("new bytes: {:X?}", new_bytes);

    // Get base address of program
    let base_addr = unsafe {
        GetModuleHandleA(core::ptr::null_mut()) as usize
    };

    // Write bytes and return success or failure
    let write_result = unsafe { WriteProcessMemory(
        GetCurrentProcess(),
        core::mem::transmute(base_addr + off_addr),
        core::mem::transmute(new_bytes.as_ptr()),
        1, 
        core::ptr::null_mut())};
    println!("Result of memory write: {}", write_result);

    // Read bytes and return success or failure
    let read_result  = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            core::mem::transmute(base_addr as usize + off_addr),
            core::mem::transmute(old_bytes.as_ptr()),
            1, 
            core::ptr::null_mut())
    };
    println!("Result of memory read: {}, with data: {:X?}", read_result, old_bytes);


}


