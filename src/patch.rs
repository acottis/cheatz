use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::memoryapi::{ReadProcessMemory,WriteProcessMemory};
use winapi::um::errhandlingapi::GetLastError;

pub struct MemoryHack<'a> {
    pub new_bytes: &'a mut [u8],
    pub old_bytes: &'a mut [u8],
    length: usize,
    target_addr: usize,
    enabled: bool,
}

impl<'a> MemoryHack<'a>{

    pub fn new(off_addr:usize, new_bytes: &'a mut [u8], old_bytes: &'a mut [u8]) -> Self{
        let len = {
            new_bytes.len()
        };
        let base_addr = unsafe { GetModuleHandleA(core::ptr::null_mut()) as usize};
        println!("Base Address: {:X}, Offset count, {:X}", base_addr, off_addr);
        Self {
            new_bytes: new_bytes,
            old_bytes: old_bytes,
            length: len,
            target_addr: base_addr + off_addr,
            enabled: false,
        }
    }

    /// Apply the patch to change target bytes to our hack
    pub fn patch_bytes(&mut self) {

        println!("Starting patch Old Bytes: {:X?}, New bytes: {:X?}", self.old_bytes, self.new_bytes);
        if self.enabled == true{
            println!("Patch already enabled");
            return
        }      
        MemoryHack::read_process_memory(self.target_addr, self.old_bytes, self.length).unwrap();
        MemoryHack::write_process_memory(self.target_addr, self.new_bytes, self.length).unwrap();
        self.enabled = true;
    }

    pub fn unpatch_bytes(&mut self) {

        println!("Starting unpatch Old Bytes: {:X?}, New bytes: {:X?}", self.old_bytes, self.new_bytes);
        if self.enabled == false{
            println!("Patch not enabled yet");
        }
        MemoryHack::write_process_memory(self.target_addr, self.old_bytes, self.length).unwrap();
        self.enabled = false;
    }

    fn read_process_memory(target_addr: usize, storage_buffer: &mut [u8], buffer_length: usize) -> Result<&str, MemoryRWError>{

        let result = unsafe { 
            ReadProcessMemory(
            GetCurrentProcess(),
            core::mem::transmute(target_addr),
            core::mem::transmute(storage_buffer.as_ptr()),
            buffer_length, 
            core::ptr::null_mut()) 
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

    fn write_process_memory(target_addr: usize, storage_buffer: &mut [u8], buffer_length: usize) -> Result<&str, MemoryRWError>{
        let result = unsafe { 
            WriteProcessMemory(
            GetCurrentProcess(),
            core::mem::transmute(target_addr),
            core::mem::transmute(storage_buffer.as_ptr()),
            buffer_length, 
            core::ptr::null_mut())};

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

// impl core::fmt::Display for PatchStatus{
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         match self {
//             PatchStatus::CantRead => write!(f, "Can not read from target memory"),
//             PatchStatus::CantWrite => write!(f, "Can not write to target memory"),
//         }
//     }
// }

