#[warn(missing_docs)]

use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::memoryapi::{ReadProcessMemory,WriteProcessMemory};
use winapi::um::errhandlingapi::GetLastError;

pub struct MemoryHack {
    pub new_bytes: Vec<u8>,
    pub old_bytes: Vec<u8>,
    length: usize,
    target_addr: usize,
    enabled: bool,
}

impl MemoryHack{

    // Initialise a new hack
    pub fn new(off_addr:usize, bytes: &[u8]) -> Self{
        let exe_base_addr = unsafe { GetModuleHandleA(core::ptr::null_mut()) as usize};
        println!("Base Address: {:X}, Offset count, {:X}", exe_base_addr, off_addr);

        let size = bytes.len();
        let mut new_bytes = Vec::new();

        for byte in 0..bytes.len(){
            new_bytes.push(bytes[byte]);
        }
        Self {
            new_bytes: new_bytes,
            old_bytes: vec![0u8; size],
            length: size,
            target_addr: exe_base_addr + off_addr,
            enabled: false,
        }
    }

    // // TODO - Cave will be offset from DLL Address?
    // pub fn trampoline_byes(&mut self)  {

    //     let dll_base_addr = unsafe { GetModuleHandleA("cheatlib\0".as_ptr() as *const i8) as usize};
    //     let exe_base_addr = unsafe { GetModuleHandleA(core::mem::zeroed()) as usize};
    //     const CAVE: usize = 0x36A50B; // Offset to .exe codecave
        
    //     println!("Starting patch Old Bytes: {:X?}, New bytes: {:X?}", self.old_bytes, self.new_bytes);
    //     if self.enabled == true{
    //         println!("Patch already enabled");
    //         return
    //     }      
        
    //     println!("Dll:{:X}, Cave:{:X}, Target: {:X}", exe_base_addr, CAVE, exe_base_addr+CAVE);
        
    //     MemoryHack::read_process_memory(exe_base_addr+CAVE, &self.old_bytes, self.length).unwrap();
    //     MemoryHack::write_process_memory(exe_base_addr+CAVE, &self.new_bytes, self.length).unwrap();

    //     self.enabled = true;
    // }

    // #[no_mangle]
    // fn test() -> !{
    //     loop {

    //     }
    // }

    /// Apply the patch to change target bytes to our hack
    pub fn patch_bytes(&mut self) {

        println!("Starting patch Old Bytes: {:X?}, New bytes: {:X?}", self.old_bytes, self.new_bytes);
        if self.enabled == true{
            println!("Patch already enabled");
            return
        }      
        MemoryHack::read_process_memory(self.target_addr, &self.old_bytes, self.length).unwrap();
        MemoryHack::write_process_memory(self.target_addr, &self.new_bytes, self.length).unwrap();
        self.enabled = true;
    }

    // Removes our memory hack by placing the old bytes back
    pub fn unpatch_bytes(&mut self) {

        println!("Starting unpatch new Bytes: {:X?}, old bytes: {:X?}", self.old_bytes, self.new_bytes);
        if self.enabled == false{
            println!("Patch not enabled yet");
            return
        }
        MemoryHack::write_process_memory(self.target_addr, &self.old_bytes, self.length).unwrap();
        self.enabled = false;
    }

    // Oxidation of winapi ReadProcessMemory
    fn read_process_memory(target_addr: usize, storage_buffer: &Vec<u8>, buffer_length: usize) -> Result<&'static str, MemoryRWError>{

        let result = unsafe { 
            ReadProcessMemory(
                GetCurrentProcess(),
                core::mem::transmute(target_addr),
                core::mem::transmute(storage_buffer.as_ptr()),
                buffer_length, 
                core::ptr::null_mut()
            ) 
        };

        println!("Result of memory read: {}, with data: {:X?}", result, storage_buffer);

        match result {
            1 => Ok("Memory Read Sucessful"),
            _ => {
                println!("Last error when reading: {}",unsafe {GetLastError()});
                Err(MemoryRWError::CantRead)
            }
        }
    }

    // Oxidation of winapi WriteProcessMemory
    fn write_process_memory(target_addr: usize, storage_buffer: &Vec<u8>, buffer_length: usize) -> Result<&'static str, MemoryRWError>{
        let result = unsafe { 
            WriteProcessMemory(
                GetCurrentProcess(),
                core::mem::transmute(target_addr),
                core::mem::transmute(storage_buffer.as_ptr()),
                buffer_length, 
                core::ptr::null_mut()
            )
        };

        println!("Result of memory write: {}", result);

        match result {
            1 => Ok("Memory Write Sucessful"),
            _ => {
                println!("Last error when writing: {}",unsafe {GetLastError()});
                Err(MemoryRWError::CantRead)
            }
        }
    }

}

#[derive(Debug)]
#[allow(dead_code)]
pub enum MemoryRWError{
    CantWrite,
    CantRead,
}
