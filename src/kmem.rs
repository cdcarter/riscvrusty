
use core::ptr::null_mut;

use crate::page::{zalloc, Table, PAGE_SIZE};

static mut KMEM_PAGE_TABLE: *mut Table = null_mut();

pub fn get_page_table() -> *mut Table {
	unsafe { KMEM_PAGE_TABLE as *mut Table }
}

pub fn init() {
    unsafe {
        KMEM_PAGE_TABLE = zalloc(1) as *mut Table;
    }
}