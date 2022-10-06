extern crate kvm_bindings;
extern crate kvm_ioctls;

use anyhow::Result;
use kvm_ioctls::Kvm;
use kvm_ioctls::VcpuExit;

pub fn run() -> Result<()> {
    use std::io::Write;
    use std::ptr::null_mut;
    use std::slice;

    use kvm_bindings::kvm_userspace_memory_region;

    let mem_size = 0x4000;
    let guest_addr = 0x1000;

    let asm_code: &[u8] = &[
        // mov $0x3f8, %dx
        0xba, 0xf8, 0x03, // add %bl, %al
        0x00, 0xd8, // add $'0', %al
        0x04, b'0', // out %al, (%dx)
        0xee, // mov $'\n', %al
        0xb0, b'\0', // out %al, (%dx)
        0xee,  // hlt
        0xf4,
    ];

    // 1. Instantiate KVM.
    let kvm = Kvm::new().unwrap();

    // 2. Create a VM.
    let vm = kvm.create_vm().unwrap();

    // 3. Initialize Guest Memory.
    let load_addr: *mut u8 = unsafe {
        libc::mmap(
            null_mut(),
            mem_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        ) as *mut u8
    };

    let slot = 0;

    let mem_region = kvm_userspace_memory_region {
        slot,
        guest_phys_addr: guest_addr,
        memory_size: mem_size as u64,
        userspace_addr: load_addr as u64,
        flags: 0,
    };
    unsafe { vm.set_user_memory_region(mem_region).unwrap() };

    // Write the code in the guest memory. This will generate a dirty page.
    unsafe {
        let mut slice = slice::from_raw_parts_mut(load_addr, mem_size);
        _ = slice.write(asm_code).unwrap();
    }

    // 4. Create one vCPU.
    let vcpu_fd = vm.create_vcpu(0).unwrap();

    // 5. Initialize general purpose and special registers.

    let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

    let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
    vcpu_regs.rip = guest_addr;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 3;
    vcpu_regs.rflags = 2;
    vcpu_fd.set_regs(&vcpu_regs).unwrap();

    // 6. Run code on the vCPU.
    loop {
        match vcpu_fd.run().expect("run failed") {
            VcpuExit::IoOut(addr, data) => {
                println!(
                    "Received an I/O out exit. Address: {:#x}. Data: {:#x}",
                    addr, data[0],
                );
            }
            VcpuExit::Hlt => {
                println!("Received a Halt exit.");
                break;
            }
            r => panic!("Unexpected exit reason: {:?}", r),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_kvm() {
        assert!(run().is_ok());
    }
}
