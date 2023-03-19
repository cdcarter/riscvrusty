// Risky OS, by cdcarter
// forked from
// Steve Operating System
// Stephen Marz
// 21 Sep 2019
#![no_std]
#![no_main]
#![feature(panic_info_message)]

use core::arch::asm;
use core::arch::global_asm;

global_asm!(include_str!("asm/boot.S"));
global_asm!(include_str!("asm/trap.S"));
global_asm!(include_str!("asm/mem.S"));

// ///////////////////////////////////
// / RUST MACROS
// ///////////////////////////////////
#[macro_export]
macro_rules! print
{
	($($args:tt)+) => ({
		use core::fmt::Write;
		let _ = write!(crate::uart::Uart::new(0x1000_0000), $($args)+);
	});
}
#[macro_export]
macro_rules! println
{
	() => ({
		print!("\r\n")
	});
	($fmt:expr) => ({
		print!(concat!($fmt, "\r\n"))
	});
	($fmt:expr, $($args:tt)+) => ({
		print!(concat!($fmt, "\r\n"), $($args)+)
	});
}

// ///////////////////////////////////
// / LANGUAGE STRUCTURES / FUNCTIONS
// ///////////////////////////////////
#[no_mangle]
extern "C" fn eh_personality() {}
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print!("Aborting: ");
    if let Some(p) = info.location() {
        println!(
            "line {}, file {}: {}",
            p.line(),
            p.file(),
            info.message().unwrap()
        );
    } else {
        println!("no information available.");
    }
    abort();
}
#[no_mangle]
extern "C" fn abort() -> ! {
    loop {
        unsafe {
            asm!("wfi");
        }
    }
}

// ///////////////////////////////////
// / CONSTANTS
// ///////////////////////////////////
extern "C" {
    static TEXT_START: usize;
    static TEXT_END: usize;
    static DATA_START: usize;
    static DATA_END: usize;
    static RODATA_START: usize;
    static RODATA_END: usize;
    static BSS_START: usize;
    static BSS_END: usize;
    static KERNEL_STACK_START: usize;
    static KERNEL_STACK_END: usize;
    static HEAP_START: usize;
    static HEAP_SIZE: usize;
}

fn print_memory_map() {
    println!("RISC-V Virt Memory Map");
    unsafe {
        println!("TEXT:   0x{:x} -> 0x{:x}", TEXT_START, TEXT_END);
        println!("RODATA: 0x{:x} -> 0x{:x}", RODATA_START, RODATA_END);
        println!("DATA:   0x{:x} -> 0x{:x}", DATA_START, DATA_END);
        println!("BSS:    0x{:x} -> 0x{:x}", BSS_START, BSS_END);
        println!(
            "STACK:  0x{:x} -> 0x{:x}",
            KERNEL_STACK_START, KERNEL_STACK_END
        );
        println!(
            "HEAP:   0x{:x} -> 0x{:x}",
            HEAP_START,
            HEAP_START + HEAP_SIZE
        );
    }
    println!();
}

#[allow(dead_code)]
fn page_allocation_fun() {
    println!("allocating 1 pages: {:p}", page::zalloc(1));
    println!("allocating 2 pages: {:p}", page::zalloc(2));
    println!("allocating 3 pages: {:p}", page::zalloc(3));
    let freeable = page::zalloc(2);
    println!("allocating 2 pages: {:p} ** this will be freed", freeable);
    println!("allocating 4 pages: {:p}", page::zalloc(4));
    page::print_page_allocations();

    println!("deallocating 2 pages: {:p}", freeable);
    page::dalloc(freeable);
    page::print_page_allocations();
    println!("allocating 4 pages: {:p}", page::zalloc(4));
    println!("allocating 1 pages: {:p}", page::zalloc(1));
    println!("allocating 1 pages: {:p}", page::zalloc(1));
    page::print_page_allocations();
}

pub fn id_map_range(root: &mut page::Table, start: usize, end: usize, bits: i64) {
    let mut memaddr = start & !(page::PAGE_SIZE - 1);
    let num_kb_pages = (page::align_val(end, 12) - memaddr) / page::PAGE_SIZE;

    // I named this num_kb_pages for future expansion when
    // I decide to allow for GiB (2^30) and 2MiB (2^21) page
    // sizes. However, the overlapping memory regions are causing
    // nightmares.
    for _ in 0..num_kb_pages {
        page::map(root, memaddr, memaddr, bits, 0);
        memaddr += 1 << 12;
    }
}
// ///////////////////////////////////
// / ENTRY POINT
// ///////////////////////////////////
#[no_mangle]
extern "C" fn kinit() {
    // Main should initialize all sub-systems and get
    // ready to start scheduling. The last thing this
    // should do is start the timer.

    let mut board_uart = uart::Uart::new(0x1000_0000);
    board_uart.init();

    print_memory_map();

    page::init();
    kmem::init();

    let root_ptr = kmem::get_page_table();
    let root_u = root_ptr as usize;
    let mut root = unsafe { root_ptr.as_mut().unwrap() };

    unsafe {
        // Map heap descriptors
        let num_pages = HEAP_SIZE / page::PAGE_SIZE;
        id_map_range(
            &mut root,
            HEAP_START,
            HEAP_START + num_pages,
            page::EntryBits::ReadWrite.val(),
        );
        // Map executable section
        id_map_range(
            &mut root,
            TEXT_START,
            TEXT_END,
            page::EntryBits::ReadExecute.val(),
        );
        // Map rodata section
        // We put the ROdata section into the text section, so they can
        // potentially overlap however, we only care that it's read
        // only.
        id_map_range(
            &mut root,
            RODATA_START,
            RODATA_END,
            page::EntryBits::ReadExecute.val(),
        );
        // Map data section
        id_map_range(
            &mut root,
            DATA_START,
            DATA_END,
            page::EntryBits::ReadWrite.val(),
        );
        // Map bss section
        id_map_range(
            &mut root,
            BSS_START,
            BSS_END,
            page::EntryBits::ReadWrite.val(),
        );
        // Map kernel stack
        id_map_range(
            &mut root,
            KERNEL_STACK_START,
            KERNEL_STACK_END,
            page::EntryBits::ReadWrite.val(),
        );
    }

    // UART
    page::map(
        &mut root,
        0x1000_0000,
        0x1000_0000,
        page::EntryBits::ReadWrite.val(),
        0,
    );

    // CLINT
    //  -> MSIP
    page::map(
        &mut root,
        0x0200_0000,
        0x0200_0000,
        page::EntryBits::ReadWrite.val(),
        0,
    );
    //  -> MTIMECMP
    page::map(
        &mut root,
        0x0200_b000,
        0x0200_b000,
        page::EntryBits::ReadWrite.val(),
        0,
    );
    //  -> MTIME
    page::map(
        &mut root,
        0x0200_c000,
        0x0200_c000,
        page::EntryBits::ReadWrite.val(),
        0,
    );
    // PLIC
    id_map_range(
        &mut root,
        0x0c00_0000,
        0x0c00_2000,
        page::EntryBits::ReadWrite.val(),
    );
    id_map_range(
        &mut root,
        0x0c20_0000,
        0x0c20_8000,
        page::EntryBits::ReadWrite.val(),
    );
    page::print_page_allocations();
    // The following shows how we're going to walk to translate a virtual
    // address into a physical address. We will use this whenever a user
    // space application requires services. Since the user space application
    // only knows virtual addresses, we have to translate silently behind
    // the scenes.
    let p = 0x8005_7000 as usize;
    let m = page::virt_to_phys(&root, p).unwrap_or(0);
    println!("Walk 0x{:x} = 0x{:x}", p, m);

    //page_allocation_fun();

    // set a value you can see on the register monitor. for fun.
    unsafe { asm!("li t6, 0xdeadbeef") };

    let root_ppn = root_u >> 12;
    let satp_val = 8 << 60 | root_ppn;
    println!("setting SATP register to {:x}", satp_val);
    unsafe {
        asm!("csrw satp, {}", in(reg) satp_val);
		asm!("sfence.vma zero, {}", in(reg) 0);
    }

    println!("<kinit>: Complete");
}

#[no_mangle]
extern "C" fn kmain() {
    let mut board_uart = uart::Uart::new(0x1000_0000);
    board_uart.init();

    println!("hello from kmain");
}

#[no_mangle]
extern "C" fn kinit_hart() {
    // this is the entry point for the non-primary harts, i guess.
    unsafe { asm!("wfi") };
}

// ///////////////////////////////////
// / RUST MODULES
// ///////////////////////////////////

pub mod cpu;
pub mod kmem;
pub mod page;
pub mod trap;
pub mod uart;
