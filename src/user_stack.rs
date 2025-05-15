//! Initialize the user stack for the application
//!
//! The structure of the user stack is described in the following figure:
//! position            content                     size (bytes) + comment
//!   ------------------------------------------------------------------------
//! stack pointer ->  [ argc = number of args ]     8
//!                   [ argv[0] (pointer) ]         8   (program name)
//!                   [ argv[1] (pointer) ]         8
//!                   [ argv[..] (pointer) ]        8 * x
//!                   [ argv[n - 1] (pointer) ]     8
//!                   [ argv[n] (pointer) ]         8   (= NULL)
//!                   [ envp[0] (pointer) ]         8
//!                   [ envp[1] (pointer) ]         8
//!                   [ envp[..] (pointer) ]        8
//!                   [ envp[term] (pointer) ]      8   (= NULL)
//!                   [ auxv[0] (Elf32_auxv_t) ]    16
//!                   [ auxv[1] (Elf32_auxv_t) ]    16
//!                   [ auxv[..] (Elf32_auxv_t) ]   16
//!                   [ auxv[term] (Elf32_auxv_t) ] 16  (= AT_NULL vector)
//!                   [ padding ]                   0 - 16
//!                   [ argument ASCIIZ strings ]   >= 0
//!                   [ environment ASCIIZ str. ]   >= 0
//!
//! (0xbffffff8)      [ end marker ]                8   (= NULL)
//!
//! (0xc0000000)      < bottom of stack >           0   (virtual)
//!
//! More details can be found in the link: <https://articles.manugarg.com/aboutelfauxiliaryvectors.html>

extern crate alloc;

use alloc::{string::String, vec::Vec};
use memory_addr::VirtAddr;

use crate::auxv::{AuxvEntry, AuxvType};

struct UserStack {
    sp: usize,
}

impl UserStack {
    pub fn new(sp: usize) -> Self {
        Self { sp }
    }
    fn push(&mut self, src: &[u8], stack_data: &mut Vec<u8>) {
        self.sp -= src.len();
        // let mut target_data = src.to_vec();
        // target_data.append(stack_data);
        // *stack_data = target_data;
        stack_data.splice(0..0, src.iter().cloned());
    }
    pub fn push_usize_slice(&mut self, src: &[usize], stack_data: &mut Vec<u8>) {
        for val in src.iter().rev() {
            let bytes = val.to_le_bytes();
            self.push(&bytes, stack_data);
        }
    }
    pub fn push_str(&mut self, str: &str, stack_data: &mut Vec<u8>) -> usize {
        self.push(b"\0", stack_data);

        self.push(str.as_bytes(), stack_data);
        self.sp
    }
    pub fn get_sp(&self) -> usize {
        self.sp
    }
}

fn init_stack(args: &[String], envs: &[String], auxv: &mut [AuxvEntry], sp: usize) -> Vec<u8> {
    let mut data = Vec::new();
    let mut stack = UserStack::new(sp);
    // define a random string with 16 bytes
    stack.push("0123456789abcdef".as_bytes(), &mut data);
    let random_str_pos = stack.get_sp();
    // Push arguments and environment variables
    let envs_slice: Vec<_> = envs
        .iter()
        .map(|env| stack.push_str(env, &mut data))
        .collect();
    let argv_slice: Vec<_> = args
        .iter()
        .map(|arg| stack.push_str(arg, &mut data))
        .collect();
    let padding_null = "\0".repeat(8);
    stack.push(padding_null.as_bytes(), &mut data);

    stack.push("\0".repeat(stack.get_sp() % 16).as_bytes(), &mut data);

    // Align stack to 16 bytes by padding if needed.
    // We will push following 8-byte items into stack:
    // - auxv (each entry is 2 * usize, so item count = auxv.len() * 2)
    // - envp (len + 1 for NULL terminator)
    // - argv (len + 1 for NULL terminator)
    // - argc (1 item)
    // Total items = auxv.len() * 2 + (envs.len() + 1) + (args.len() + 1) + 1
    //             = auxv.len() * 2 + envs.len() + args.len() + 3
    // If odd, the stack top will not be aligned to 16 bytes unless we add 8-byte padding
    if (envs.len() + args.len() + 3) & 1 != 0 {
        stack.push(padding_null.as_bytes(), &mut data);
    }

    // Push auxiliary vectors
    for auxv_entry in auxv.iter_mut() {
        if auxv_entry.get_type() == AuxvType::RANDOM {
            *auxv_entry.value_mut_ref() = random_str_pos;
        }
        if auxv_entry.get_type() == AuxvType::EXECFN {
            *auxv_entry.value_mut_ref() = argv_slice[0];
        }
    }
    stack.push_usize_slice(
        unsafe {
            core::slice::from_raw_parts(
                auxv.as_ptr() as *const usize,
                core::mem::size_of_val(auxv) / core::mem::size_of::<usize>(),
            )
        },
        &mut data,
    );

    // Push the argv and envp pointers
    stack.push(padding_null.as_bytes(), &mut data);
    stack.push_usize_slice(envs_slice.as_slice(), &mut data);
    stack.push(padding_null.as_bytes(), &mut data);
    stack.push_usize_slice(argv_slice.as_slice(), &mut data);
    // Push argc
    stack.push_usize_slice(&[args.len()], &mut data);
    assert!(stack.get_sp() % 16 == 0);
    data
}

/// Generate initial stack frame for user stack
///
/// # Arguments
///
/// * `args` - Arguments of the application
/// * `envs` - Environment variables of the application
/// * `auxv` - Auxiliary vectors of the application
/// * `stack_base` - Lowest address of the stack
/// * `stack_size` - Size of the stack.
///
/// # Return
///
/// * [`Vec<u8>`] - Initial stack frame of the application
///
/// # Notes
///
/// The detailed format is described in <https://articles.manugarg.com/aboutelfauxiliaryvectors.html>
pub fn app_stack_region(
    args: &[String],
    envs: &[String],
    auxv: &mut [AuxvEntry],
    stack_base: VirtAddr,
    stack_size: usize,
) -> Vec<u8> {
    let ustack_bottom = stack_base;
    let ustack_top = ustack_bottom + stack_size;
    init_stack(args, envs, auxv, ustack_top.into())
}
