/*use nix::libc::siginfo_t;
use std::error::Error;
use std::os::raw::{c_int, c_void};

mod runner;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    // map pages
}

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    // read ELF segments

    // print segments

    // determine base address

    // determine entry point

    // register SIGSEGV handler

    // run ELF using runner::exec_run

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // load ELF provided within the first argument
    Ok(())
}
*/

use nix::libc::siginfo_t;
use nix::libc::{siginfo_t, Elf32_Ehdr, Elf32_Phdr};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::os::raw::{c_int, c_void};
use std::ptr;
use nix::sys::mman::{mmap, munmap, mprotect, MapFlags, ProtFlags};

mod runner;

struct Segment {
    vaddr: usize,
    mem_size: usize,
    offset: usize,
    file_size: usize, 
    flags: String,
    file: File,
}

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void){
    let address = unsafe {(*siginfo).si_addr()} as usize;
    if let Some(segment) = find_segment(address){
        if segment.is_mapped(address){
            eprintln!("Unauthorized memory access at address 0x{:x}", address);
            std::process::exit(-200);
        } else {
            let page_start = address & !(4095);
            let prot = get_prot_flags(&segment.flags);
            let mapped_addr = unsafe{
                mmap(
                    page_start as *mut c_void,
                    4096,
                    prot,
                    MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE,
                    segment.file.as_raw_fd(),
                    (segment.offset as isize + (page_start-segment.vaddr) as isize) as i64,
                )
            };
            if mapped_addr.is_err() {
                eprintln!("Failed to map memory at address 0x{:x}", address);
                std::process::exit(-200);
            }
        }
    } else {
        eprintln!("Invalid memory access at address 0x:{x}", address);
        std::process::exit(-200);
    }
}

fn find_segment(address: usize) -> Option<&'static Segment>{
    SEGMENTS.iter().find(|segment|{address >= segment.vaddr && address < segment.vaddr+segment.mem_size})
}

fn get_prot_flags(flags: &str) -> ProtFlags {
    let mut prot = ProtFlags::empty();
    if flags.contains('r'){
        prot |= ProtFlags::PROT_READ;
    }
    if flags.contains('w'){
        prot |= ProtFlags::PROT_WRITE;
    }
    if flags.contains('x'){
        prot |= ProtFlags::PROT_EXEC;
    }
    prot
}



fn exec(filename: &str) -> Result<(),Box<dyn Error>> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let elf = ElfFile32::parse(&buffer)?;

    eprintln!("Segments");
    for (i, segment) in elf.segments.iter().enumerate() {
        eprintln!(
            "{}\t0x{:x}\t{}\t0x{:x}\t{}\t{}",
            i,
            segment.vaddr,
            segment.mem_size,
            segment.offset,
            segment.file_size,
            segment.flags
        );
    }
    let base_address = elf.segments.iter().map(|s| s.vaddr).min().unwrap_or(0);
    eprintln!("Base address 0x{:x}", base_address);
    let entry_point = elf.entry;
    eprintln!("Entry point 0x{:x}", entry_point);
    unsafe{
        let mut sa: nix::libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigsegv_handler as usize;
        sa.sa_flags = nix::libc::SA_SIGINFO;
        nix::libc::sigaction(nix::libc::SIGSEGV, &sa, ptr::null_mut());
    }

    SEGMENTS = elf.segments.into_iter().map(|s| Segment{
        vaddr: s.vaddr,
        mem_size: s.mem_size,
        offset: s.offset,
        file_size: s.file_size,
        flags: s.flags,
        file: file.try_clone()?,
    }).collect();

    runner::exec_run(base_address, entry_point);
    Ok(())
}

fn main() ->> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <executable>", args[0]);
        std::process::exit(1);
    }
    exec(&args[1])?;
    Ok(())
}