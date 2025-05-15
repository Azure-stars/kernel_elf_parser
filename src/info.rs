//! ELF information parsed from the ELF file
//!

extern crate alloc;
use alloc::vec::Vec;

use memory_addr::VirtAddr;
use page_table_entry::MappingFlags;

use crate::auxv::{AuxvEntry, AuxvType};

/// ELF Program Header applied to the kernel
///
/// Details can be seen in the [ELF Program Header](https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html)
pub struct ELFPH {
    /// The start offset of the segment in the ELF file
    pub offset: usize,
    /// The destination virtual address of the segment in the kernel memory
    pub vaddr: VirtAddr,
    /// Memory size of the segment
    pub memsz: u64,
    /// File size of the segment
    pub filesz: u64,
    /// [`MappingFlags`] of the segment which is used to set the page table entry
    pub flags: MappingFlags,
}

/// A wrapper for the ELF file data with some useful methods.
pub struct ELFParser<'a> {
    elf: &'a xmas_elf::ElfFile<'a>,
    /// Base address of the ELF file loaded into the memory.
    base: usize,
}

impl<'a> ELFParser<'a> {
    fn elf_base_addr(elf: &xmas_elf::ElfFile, interp_base: usize) -> Result<usize, &'static str> {
        match elf.header.pt2.type_().as_type() {
            // static
            xmas_elf::header::Type::Executable => Ok(0),
            // dynamic
            xmas_elf::header::Type::SharedObject => {
                match elf
                    .program_iter()
                    .filter(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Interp))
                    .count()
                {
                    // Interpreter invoked by the ELF file.
                    0 => Ok(interp_base),
                    // Dynamic ELF file
                    1 => Ok(0),
                    _ => Err("Multiple interpreters found"),
                }
            }
            _ => Err("Unsupported ELF type"),
        }
    }

    /// Create a new `ELFInfo` instance.
    /// # Arguments
    /// * `elf` - The ELF file data
    /// * `interp_base` - Address of the interpreter if the ELF file is a dynamic executable
    /// * `bias` - Bias for the base address of the PIE executable.
    /// * `uspace_base` - The lowest address of the user space
    ///
    /// # Note
    /// If the ELF file is a dynamic executable, the `interp_base` should be the address of the interpreter, and the address of the ELF file will be `elf.base_addr() + bias`.
    pub fn new(
        elf: &'a xmas_elf::ElfFile,
        interp_base: usize,
        bias: Option<isize>,
        uspace_base: usize,
    ) -> Result<Self, &'static str> {
        if elf.header.pt1.magic.as_slice() != b"\x7fELF" {
            return Err("invalid elf!");
        }

        // Check if the ELF file is a Position Independent Executable (PIE)
        let is_pie = elf.header.pt2.type_().as_type() == xmas_elf::header::Type::SharedObject
            || (elf.header.pt2.type_().as_type() == xmas_elf::header::Type::Executable
                && elf
                    .program_iter()
                    .any(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Interp)));

        // If it is not PIE, and the lowest address is less than user space base, it is invalid.
        if !is_pie
            && elf.program_iter().any(|ph| {
                ph.get_type() == Ok(xmas_elf::program::Type::Load)
                    && ph.virtual_addr() < uspace_base as u64
            })
        {
            return Err("Invalid ELF base address");
        }

        let mut base = Self::elf_base_addr(elf, interp_base)?;
        if is_pie {
            base = base.wrapping_add(bias.unwrap_or(0) as usize);
        }
        Ok(Self { elf, base })
    }

    /// The entry point of the ELF file.
    pub fn entry(&self) -> usize {
        self.elf.header.pt2.entry_point() as usize + self.base
    }

    /// The number of program headers in the ELF file.
    pub fn phnum(&self) -> usize {
        self.elf.header.pt2.ph_count() as usize
    }

    /// The size of the program header table entry in the ELF file.
    pub fn phent(&self) -> usize {
        self.elf.header.pt2.ph_entry_size() as usize
    }

    /// The offset of the program header table in the ELF file.
    pub fn phdr(&self) -> usize {
        self.elf.header.pt2.ph_offset() as usize
            + self.base
            + self
                .elf
                .program_iter()
                .find(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Load))
                .map(|ph| ph.virtual_addr() as usize)
                .unwrap_or(0)
    }

    /// The base address of the ELF file loaded into the memory.
    pub fn base(&self) -> usize {
        self.base
    }

    /// The ref of the ELF file data.
    pub fn elf(&self) -> &xmas_elf::ElfFile {
        self.elf
    }

    /// Part of auxiliary vectors from the ELF file.
    ///
    /// # Arguments
    ///
    /// * `pagesz` - The page size of the system
    ///
    /// Details about auxiliary vectors are described in <https://articles.manugarg.com/aboutelfauxiliaryvectors.html>
    pub fn auxv_vector(&self, pagesz: usize) -> [AuxvEntry; 17] {
        [
            AuxvEntry::new(AuxvType::PHDR, self.phdr()),
            AuxvEntry::new(AuxvType::PHENT, self.phent()),
            AuxvEntry::new(AuxvType::PHNUM, self.phnum()),
            AuxvEntry::new(AuxvType::PAGESZ, pagesz),
            AuxvEntry::new(AuxvType::BASE, self.base()),
            AuxvEntry::new(AuxvType::FLAGS, 0),
            AuxvEntry::new(AuxvType::ENTRY, self.entry()),
            AuxvEntry::new(AuxvType::HWCAP, 0),
            AuxvEntry::new(AuxvType::CLKTCK, 100),
            AuxvEntry::new(AuxvType::PLATFORM, 0),
            AuxvEntry::new(AuxvType::UID, 0),
            AuxvEntry::new(AuxvType::EUID, 0),
            AuxvEntry::new(AuxvType::GID, 0),
            AuxvEntry::new(AuxvType::EGID, 0),
            AuxvEntry::new(AuxvType::RANDOM, 0),
            AuxvEntry::new(AuxvType::EXECFN, 0),
            AuxvEntry::new(AuxvType::NULL, 0),
        ]
    }

    /// Read all [`self::ELFPH`] with `LOAD` type of the elf file.
    pub fn ph_load(&self) -> Vec<ELFPH> {
        let mut segments = Vec::new();
        // Load Elf "LOAD" segments at base_addr.
        self.elf
            .program_iter()
            .filter(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Load))
            .for_each(|ph| {
                let start_va = ph.virtual_addr() as usize + self.base;
                let start_offset = ph.offset() as usize;
                let mut flags = MappingFlags::USER;
                if ph.flags().is_read() {
                    flags |= MappingFlags::READ;
                }
                if ph.flags().is_write() {
                    flags |= MappingFlags::WRITE;
                }
                if ph.flags().is_execute() {
                    flags |= MappingFlags::EXECUTE;
                }
                segments.push(ELFPH {
                    offset: start_offset,
                    vaddr: VirtAddr::from(start_va),
                    memsz: ph.mem_size(),
                    filesz: ph.file_size(),
                    flags,
                });
            });
        segments
    }
}
