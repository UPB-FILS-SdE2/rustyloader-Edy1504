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
/*
use nix::libc::{siginfo_t, sigaction, SIGSEGV, SA_SIGINFO};
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
*/

use nix::libc::{sigaction, siginfo_t, SIGSEGV, SA_SIGINFO};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::os::raw::{c_int, c_void};
use std::path::Path;
use std::sync::Mutex;
use object::{Object, ObjectSegment};

mod runner;

#[derive(Clone)]
struct Segment {
    vaddr: usize,
    mem_size: usize,
    offset: usize,
    file_size: usize,
    flags: String,
    file: File,
}

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;

    // Handle the page fault here
    if let Some(seg) = SEGMENTS.lock().unwrap().iter().find(|seg| address >= seg.vaddr && address < seg.vaddr + seg.mem_size) {
        let offset = address - seg.vaddr;
        let page_start = address & !0xfff;
        let page_offset = offset & 0xfff;
        let page_size = 4096;

        let mut buffer = vec![0u8; page_size];
        let mut file = seg.file.try_clone().unwrap();
        file.seek(std::io::SeekFrom::Start((seg.offset + page_offset) as u64)).unwrap();
        file.read_exact(&mut buffer[..]).unwrap();

        let prot = (if seg.flags.contains('r') { nix::libc::PROT_READ } else { 0 })
            | (if seg.flags.contains('w') { nix::libc::PROT_WRITE } else { 0 })
            | (if seg.flags.contains('x') { nix::libc::PROT_EXEC } else { 0 });

        unsafe {
            let result = nix::libc::mmap(
                page_start as *mut c_void,
                page_size,
                prot,
                nix::libc::MAP_FIXED | nix::libc::MAP_PRIVATE | nix::libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if result == nix::libc::MAP_FAILED {
                eprintln!("mmap failed: {}", std::io::Error::last_os_error());
                std::process::exit(-200);
            }

            let dst = std::slice::from_raw_parts_mut(page_start as *mut u8, page_size);
            dst.copy_from_slice(&buffer);
        }
    } else {
        eprintln!("Segmentation fault at address: 0x{:x}", address);
        std::process::exit(-200);
    }
}

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    let path = Path::new(filename);
    let mut file = File::open(&path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let elf = object::File::parse(&*buffer)?;
    let mut segments = Vec::new();

    for segment in elf.segments() {
        if let Some(range) = segment.file_range() {
            let flags = format!(
                "{}{}{}",
                if segment.flags().is_read() { "r" } else { "-" },
                if segment.flags().is_write() { "w" } else { "-" },
                if segment.flags().is_execute() { "x" } else { "-" }
            );
            segments.push(Segment {
                vaddr: segment.address(),
                mem_size: segment.size(),
                offset: range.0,
                file_size: range.1 - range.0,
                flags,
                file: File::open(filename)?,
            });
        }
    }

    let base_address = segments.iter().map(|seg| seg.vaddr).min().unwrap_or(0);
    let entry_point = elf.entry();

    eprintln!("Segments");
    for (i, seg) in segments.iter().enumerate() {
        eprintln!(
            "{}\t0x{:x}\t{}\t0x{:x}\t{}\t{}",
            i,
            seg.vaddr,
            seg.mem_size,
            seg.offset,
            seg.file_size,
            seg.flags,
        );
    }

    eprintln!("Base address 0x{:x}", base_address);
    eprintln!("Entry point 0x{:x}", entry_point);

    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigsegv_handler as usize;
        sa.sa_flags = SA_SIGINFO;
        nix::libc::sigemptyset(&mut sa.sa_mask);
        sigaction(SIGSEGV, &sa, std::ptr::null_mut());
    }

    *SEGMENTS.lock().unwrap() = segments;
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