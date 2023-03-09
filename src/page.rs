use core::mem::size_of;
use core::ptr::null_mut;

use bitflags::bitflags;

extern "C" {
    // just reading these symbols is unsafe btw!
    static HEAP_START: usize;
    static HEAP_SIZE: usize;
}

static mut ALLOC_START: usize = 0;
const PAGE_ORDER: usize = 12;
pub const PAGE_SIZE: usize = 1 << 12;

pub const fn align_val(val: usize, order: usize) -> usize {
    let o = (1usize << order) - 1;
    (val + o) & !o
}

// BEGIN: Page Allocator
bitflags! {
pub struct PageBits: u8 {
    const Empty = 0;
    const Taken = 0b01;
    const Last = 0b10;
}
}

#[derive(Debug)]
pub struct Page {
    flags: u8,
}

impl Page {
    pub fn is_last(&self) -> bool {
        if self.flags & PageBits::Last.bits != 0 {
            true
        } else {
            false
        }
    }

    pub fn is_taken(&self) -> bool {
        if self.flags & PageBits::Taken.bits != 0 {
            true
        } else {
            false
        }
    }

    pub fn is_free(&self) -> bool {
        !self.is_taken()
    }

    pub fn clear(&mut self) {
        self.flags = PageBits::empty().bits;
    }

    pub fn set_flag(&mut self, flag: PageBits) {
        self.flags |= flag.bits;
    }

    pub fn clear_flag(&mut self, flag: PageBits) {
        self.flags &= !(flag.bits);
    }
}

pub fn init() {
    unsafe {
        let num_pages = HEAP_SIZE / PAGE_SIZE;
        let ptr = HEAP_START as *mut Page;

        // clear all pages all bits, just in case
        for i in 0..num_pages {
            let x = &mut (*ptr.add(i));
            x.clear();
        }

        ALLOC_START = align_val(HEAP_START + num_pages * size_of::<Page>(), PAGE_ORDER);
    }
}

pub fn alloc(pages: usize) -> *mut u8 {
    assert!(pages > 0);

    unsafe {
        let num_pages = HEAP_SIZE / PAGE_SIZE;
        let ptr = HEAP_START as *mut Page;
        let mut found = false;

        for i in 0..num_pages - pages {
            if (*ptr.add(i)).is_free() {
                found = true;
                for j in i..i + pages {
                    if !(*ptr.add(j)).is_free() {
                        found = false;
                        break;
                    }
                }
            }

            if found {
                for k in i..i + pages - 1 {
                    (*ptr.add(k)).set_flag(PageBits::Taken);
                }

                (*ptr.add(i + pages - 1)).set_flag(PageBits::Taken);
                (*ptr.add(i + pages - 1)).set_flag(PageBits::Last);

                return (ALLOC_START + PAGE_SIZE * i) as *mut u8;
            }
        }
    }

    null_mut()
}

pub fn zalloc(pages: usize) -> *mut u8 {
    let ret = alloc(pages);
    if !ret.is_null() {
        //TODO why isnt this an optional? for rust alloc hook?
        let size = (PAGE_SIZE * pages) / 8;
        let big_ptr = ret as *mut u64; // alarm alarm is this broken on 32 bit? does it matter?
        for i in 0..size {
            // we're forcing a store doubleword here to make this fast
            // probably should try asm instead?
            unsafe {
                (*big_ptr.add(i)) = 0;
            }
        }
    }
    ret
}

pub fn dalloc(ptr: *mut u8) {
    assert!(!ptr.is_null());
    unsafe {
        let addr = HEAP_START + (ptr as usize - ALLOC_START) / PAGE_SIZE;
        assert!(addr >= HEAP_START && addr < HEAP_START + HEAP_SIZE);
        let mut p = addr as *mut Page;
        while (*p).is_taken() && !(*p).is_last() {
            (*p).clear();
            p = p.add(1);
        }
        assert!((*p).is_last() == true, "Possible double-free detected");
        (*p).clear();
    }
}

pub fn print_page_allocations() {
    unsafe {
        let num_pages = HEAP_SIZE / PAGE_SIZE;
        let mut beg = HEAP_START as *const Page;
        let end = beg.add(num_pages);
        let alloc_beg = ALLOC_START;
        let alloc_end = ALLOC_START + num_pages * PAGE_SIZE;
        println!();
        println!(
            "PAGE ALLOCATION TABLE\nMETA: {:p} -> {:p}\nPHYS: \
		          0x{:x} -> 0x{:x}",
            beg, end, alloc_beg, alloc_end
        );
        println!("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        let mut num = 0;
        while beg < end {
            if (*beg).is_taken() {
                let start = beg as usize;
                let memaddr = ALLOC_START + (start - HEAP_START) * PAGE_SIZE;
                print!("0x{:x} => ", memaddr);
                loop {
                    num += 1;
                    if (*beg).is_last() {
                        let end = beg as usize;
                        let memaddr = ALLOC_START + (end - HEAP_START) * PAGE_SIZE + PAGE_SIZE - 1;
                        print!("0x{:x}: {:>3} page(s)", memaddr, (end - start + 1));
                        println!(".");
                        break;
                    }
                    beg = beg.add(1);
                }
            }
            beg = beg.add(1);
        }
        println!("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        println!(
            "Allocated: {:>5} pages ({:>9} bytes).",
            num,
            num * PAGE_SIZE
        );
        println!(
            "Free     : {:>5} pages ({:>9} bytes).",
            num_pages - num,
            (num_pages - num) * PAGE_SIZE
        );
        println!();
    }
}
// END: Page Allocator

// BEGIN: MMU

#[repr(i64)]
#[derive(Copy, Clone)]
pub enum EntryBits {
    None = 0,
    Valid = 1 << 0,
    Read = 1 << 1,
    Write = 1 << 2,
    Execute = 1 << 3,
    User = 1 << 4,
    Global = 1 << 5,
    Access = 1 << 6,
    Dirty = 1 << 7,

    // Convenience combinations
    ReadWrite = 1 << 1 | 1 << 2,
    ReadExecute = 1 << 1 | 1 << 3,
    ReadWriteExecute = 1 << 1 | 1 << 2 | 1 << 3,

    // User Convenience Combinations
    UserReadWrite = 1 << 1 | 1 << 2 | 1 << 4,
    UserReadExecute = 1 << 1 | 1 << 3 | 1 << 4,
    UserReadWriteExecute = 1 << 1 | 1 << 2 | 1 << 3 | 1 << 4,
}

// Helper functions to convert the enumeration
// into an i64, which is what our page table
// entries will be.
impl EntryBits {
    pub fn val(self) -> i64 {
        self as i64
    }
}

pub struct Entry {
    pub entry: i64,
}

impl Entry {
    pub fn is_valid(&self) -> bool {
        self.get_entry() & EntryBits::Valid.val() != 0
    }

    pub fn is_invalid(&self) -> bool {
        !self.is_valid()
    }

    pub fn is_leaf(&self) -> bool {
        self.get_entry() & 0xe != 0
    }

    pub fn is_branch(&self) -> bool {
        !self.is_leaf()
    }

    // todo this is weird and i don't like it! fwiw!
    pub fn set_entry(&mut self, new_entry: i64) {
        self.entry = new_entry
    }

    pub fn get_entry(&self) -> i64 {
        self.entry
    }
}

pub struct Table {
    pub entries: [Entry; 512],
}

impl Table {
    pub fn len() -> usize {
        512
    }
}

pub fn map(root: &mut Table, vaddr: usize, paddr: usize, bits: i64, level: usize) {
    assert!(bits & 0xe != 0);
    let vpn = [
        // VPN[0] = vaddr[20:12]
        (vaddr >> 12) & 0x1ff,
        // VPN[1] = vaddr[29:21]
        (vaddr >> 21) & 0x1ff,
        // VPN[2] = vaddr[38:30]
        (vaddr >> 30) & 0x1ff,
    ];
    let ppn = [
        // PPN[0] = paddr[20:12]
        (paddr >> 12) & 0x1ff,
        // PPN[1] = paddr[29:21]
        (paddr >> 21) & 0x1ff,
        // PPN[2] = paddr[55:30]
        (paddr >> 30) & 0x3ff_ffff,
    ];
    let mut v = &mut root.entries[vpn[2]];
    for i in (level..2).rev() {
        if !v.is_valid() {
            let page = zalloc(1);
            v.set_entry((page as i64 >> 2) | EntryBits::Valid.val());
        }
        let entry = ((v.get_entry() & !0x3ff) << 2) as *mut Entry;
        v = unsafe { entry.add(vpn[i]).as_mut().unwrap() };
    }

    // The entry structure is Figure 4.18 in the RISC-V Privileged
    // Specification
    let entry = (ppn[2] << 28) as i64 |   // PPN[2] = [53:28]
	            (ppn[1] << 19) as i64 |   // PPN[1] = [27:19]
				(ppn[0] << 10) as i64 |   // PPN[0] = [18:10]
				bits |                    // Specified bits, such as User, Read, Write, etc
				EntryBits::Valid.val(); // Valid bit
    v.set_entry(entry);
}

pub fn unmap(root: &mut Table) {
    for lv2 in 0..Table::len() {
        let ref entry_lv2 = root.entries[lv2];
        if entry_lv2.is_valid() && entry_lv2.is_branch() {
            let memaddr_lv1 = (entry_lv2.get_entry() & !0x3ff) << 2;
            let table_lv1 = unsafe { (memaddr_lv1 as *mut Table).as_mut().unwrap() };
            for lv1 in 0..Table::len() {
                let ref entry_lv1 = table_lv1.entries[lv1];
                if entry_lv1.is_valid() && entry_lv1.is_branch() {
                    let memaddr_lv0 = (entry_lv1.get_entry() & !0x3ff) << 2;
                    dalloc(memaddr_lv0 as *mut u8);
                }
            }
            dalloc(memaddr_lv1 as *mut u8);
        }
    }
}

// walk the page table to convert vaddr to its paddr
pub fn virt_to_phys(root: &Table, vaddr: usize) -> Option<usize> {
    let vpn = [
        (vaddr >> 12) & 0x1ff,
        (vaddr >> 21) & 0x1ff,
        (vaddr >> 30) & 0x1ff,
    ];
    let mut v = &root.entries[vpn[2]];
    for i in (0..=2).rev() {
        if v.is_invalid() {
            break;
        } else if v.is_leaf() {
            // The offset mask masks off the PPN. Each PPN is 9
            // bits and they start at bit #12. So, our formula
            // 12 + i * 9

            //TODO: understand this math and the math below. why ...anything
            let off_mask = (1 << (12 + i * 9)) - 1;
            let vaddr_pgoff = vaddr & off_mask;
            let addr = ((v.get_entry() << 2) as usize) & !off_mask;
            return Some(addr | vaddr_pgoff);
        }
        let entry = ((v.get_entry() & !0x3ff) << 2) as *const Entry;
        v = unsafe { entry.add(vpn[i - 1]).as_ref().unwrap() };
    }

    None
}

// END: MMU
