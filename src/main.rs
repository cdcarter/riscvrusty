// Risky OS, by cdcarter
// forked from
// Steve Operating System
// Stephen Marz
// 21 Sep 2019
#![no_std]
#![no_main]
#![feature(panic_info_message)]

use core::arch::global_asm;
use core::arch::asm;

global_asm!(include_str!("asm/boot.S"));
global_asm!(include_str!("asm/trap.S"));
global_asm!(include_str!("asm/mem.S"));

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
	static mut KERNEL_TABLE: usize;
}
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
	}
	else {
		println!("no information available.");
	}
	abort();
}
#[no_mangle]
extern "C"
fn abort() -> ! {
	loop {
		unsafe {
			asm!("wfi");
		}
	}
}

// ///////////////////////////////////
// / CONSTANTS
// ///////////////////////////////////

// ///////////////////////////////////
// / ENTRY POINT
// ///////////////////////////////////
#[no_mangle]
extern "C"
fn kinit() {
	// Main should initialize all sub-systems and get
	// ready to start scheduling. The last thing this
	// should do is start the timer.

	let mut board_uart = uart::Uart::new(0x1000_0000);
	board_uart.init();

	println!("RISC-V Virt Memory Map");
	unsafe {
	println!("TEXT:   0x{:x} -> 0x{:x}", TEXT_START, TEXT_END);
	println!("RODATA: 0x{:x} -> 0x{:x}", RODATA_START, RODATA_END);
	println!("DATA:   0x{:x} -> 0x{:x}", DATA_START, DATA_END);
	println!("BSS:    0x{:x} -> 0x{:x}", BSS_START, BSS_END);
	println!("STACK:  0x{:x} -> 0x{:x}", KERNEL_STACK_START, KERNEL_STACK_END);
	println!("HEAP:   0x{:x} -> 0x{:x}", HEAP_START, HEAP_START+HEAP_SIZE);
	}

	page::init();

	page::alloc(1);
	page::alloc(2);
	page::alloc(3);
	let freeable = page::alloc(1);
	page::alloc(4);
	page::dalloc(freeable);
	page::alloc(4);
	page::print_page_allocations();

	unsafe {asm!("li t6, 0xdeadbeef")};
	println!("<kinit>: Complete");
}

#[no_mangle]
extern "C"
fn kinit_hart() {
	// this is the entry point for the non-primary harts, i guess.
	unsafe {asm!("wfi")};
}

// ///////////////////////////////////
// / RUST MODULES
// ///////////////////////////////////

pub mod uart;
pub mod page;