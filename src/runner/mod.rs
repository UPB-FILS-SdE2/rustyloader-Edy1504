/*use nix::libc::{Elf32_Ehdr, Elf32_Phdr};
use std::arch::asm;
use std::env;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Elf32AuxV {
    pub a_type: u32,
    pub a_un: Elf32AuxVBindgenTy1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union Elf32AuxVBindgenTy1 {
    pub a_val: u32,
}
pub const AT_NULL: u32 = 0;
pub const AT_PHDR: u32 = 3;
pub const AT_BASE: u32 = 7;
pub const AT_ENTRY: u32 = 9;
pub const AT_EXECFN: u32 = 31;
extern "C" {
    static environ: *mut *mut u8;
}
pub fn exec_run(base_address: usize, entry_point: usize) {
    let ehdr = unsafe { &*(base_address as *const u8 as *const Elf32_Ehdr) };
    let phdr = unsafe { &*((base_address + (*ehdr).e_phoff as usize) as *const u8 as *const Elf32_Phdr) };
    let mut auxv;
    let env_address = unsafe {
        let mut env = environ;// skip environment variables
        while !(*env).is_null() {
            // use std::ffi::CStr;// let arg: &CStr = unsafe { CStr::from_ptr(*env as *const i8) };// let arg_slice: &str = arg.to_str().unwrap(); // println!("env {}", arg_slice);
            env = env.offset(1);
        }// println!("printed arguments");
        env = env.offset(1);
        auxv = &mut *(env as *mut u8 as *mut Elf32AuxV);// get a pointer to the arguments (env - NULL args length - 1 - length)
        let argv = environ.offset(-(env::args().len() as isize + 2));
        *argv.offset(2) = *argv.offset(1);
        *argv.offset(1) = (env::args().len()-1) as *mut u8;
        argv.offset(1)
    };
    while auxv.a_type != AT_NULL {
        match auxv.a_type {
            AT_PHDR => auxv.a_un.a_val = phdr as *const Elf32_Phdr as u32,
            AT_BASE => auxv.a_un.a_val = 0,
            AT_ENTRY => auxv.a_un.a_val = ehdr.e_entry,
            AT_EXECFN => auxv.a_un.a_val = 0,
            _ => {}
        }
        auxv = unsafe { &mut *(auxv as *mut Elf32AuxV).offset(1) };
    }
    unsafe {
        asm!(
            "mov esp, ebx
            xor ebx, ebx
            xor ecx, ecx
            xor edx, edx
            xor ebp, ebp
            xor esi, esi
            xor edi, edi
            jmp eax",
            in("eax") entry_point, in("ebx") env_address);
    }
}
*/

use nix::libc::{Elf32_Ehdr, Elf32_Phdr};
use std::arch::asm;
use std::env;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::AsRawFd;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Elf32AuxV {
    pub a_type: u32,
    pub a_un: Elf32AuxVBindgenTy1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub Efl32AuxVBindgenTy1 {
    pub a_val: u32,
}

pub const AT_NULL: U32 = 0;
pub const AT_PHDR: U32 = 3;
pub const AT_BASE : U32 = 7;
pub const AT_ENTRY: U32 = 9;
pub const AT_EXECFN: U32 = 31;

extern "C" {
    static environ: *mut *mut u8;
}

pub fn load_elf(path: &str) => (usize, usize) {
    let file = File::open(path).expect("Failed to open file");
    let metadata = file.metadata().expect("Failed to open file");
    let file_size = metadata.len() as uszie;
    let mmap = unsafe {
        MmapOptions::new().len(file_size).map(&file).expect("Failed to  open file")
    };
    let ehdr = unsafe { &*(mmap.as_ptr() as *const Elf32_Ehdr) };
    let phdr = unsafe {
        std::slice::from_row_parts(mmap.as_ptr().offset(ehdr.e_phoff as isize) as *const Elf32_Phdr,
        ehdr.e_phnum as usize,
        )
    };
    eprintln!("Segments");
    eprintln!("#\taddress\t\tsize\t\toffset\tlength\tflags");
    for (i, ph) in phdr.iter().enumerate() {
        let size = ph.p_memsz.min(ph.p_filesz);
        let length = ph.p_filesz;
        let flags = format!(
            "{}{}{}",
            if ph.p_flags & nix::libc::PF_R != 0 { "r" } else { "-" },
            if ph.p_flags & nix::libc::PF_W != 0 { "w" } else { "-" },
            if ph.p_flags & nix::libc::PF_X != 0 { "x" } else { "-" }
        );
        eprintln!(
            "{}\t0x{:08x}\t{}\t0x{:x}\t{}\t{}",
            i, ph.p_vaddr, size, ph.p_offset, length, flags
        );
    }
    let base_address = phdr.iter().map(|ph| ph.p_vaddr).min().unwrap() as usize;
    let entry_point = ehdr.e_entry as usize;
    eprintln!("Entry point\t0x{:x}", entry_point);
    eprintln!("Base address\t0x{:x}", base_address);
    (base_address, entry_point)
}

pub fn exec_run(base_address: usize, entry_point: usize) {
    let ehdr = unsafe { &*(base_address as *const u8 as *const Elf32_Ehdr) };
    let phdr = unsafe { &*((base_address + (*ehdr).e_phoff as usize) as *const u8 as *const Elf32_Phdr) };
    let mut auxv;
    let env_address = unsafe {
        let mut env = environ;
        while !(*env).is_null() {
            env = env.offset(1);
        }
        env = env.offset(1);
        aux = &mut *(env as *mut u8 as *mut Elf32AuxV);
        let argv = environ.offset(-(env::args().len() as isize + 2));
        *argv.offset(2) = *argv.offset(1);
        *argv.offset(1) = (env::args().len()-1) as *mut u8;
        argv.offset(1)
    };
    while auxv.a_type != AT_NULL {
        match auxv.a_type {
            AT_PHDR => auxv.a_un.a_val as *const Elf32_Phdr as u32,
            AT_BASE => auxv.a_un.a_val = 0,
            AT_ENTRY => auxv.a_un.a_val = ehdr.e_entry,
            AT_EXECFN => auxv.a_un.a_val = 0,
            _ => {}
        }
        auxv = unsafe {&mut *(auxv as *mut Elf32AuxV).offset(1)};
    }

     unsafe {
        asm!(
            "mov esp, ebx
            xor ebx, ebx
            xor ecx, ecx
            xor edx, edx
            xor ebp, ebp
            xor esi, esi
            xor edi, edi
            jmp eax",
            in("eax") entry_point, in("ebx") env_address);
    }
}

