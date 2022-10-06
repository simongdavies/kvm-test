use super::kvm_regs::Regs;
use anyhow::{anyhow, bail, Result};
use core::ptr::null_mut;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Cap::UserMemory, Kvm, VcpuExit, VcpuFd, VmFd};
#[cfg(target_os = "linux")]
use libc::{mmap, munmap};

pub fn run() -> Result<()> {
    is_present()?;
    let size: usize = 0x1000;
    const GUEST_PHYS_ADDR: u64 = 0x1000;
    #[rustfmt::skip]
    const CODE: [u8; 12] = [
        // mov $0x3f8, %dx
        0xba, 0xf8, 0x03,
        // add %bl, %al
        0x00, 0xd8,
        // add $'0', %al
        0x04, b'0',
        // out %al, (%dx)
        0xee,
        // mov $'\n', %al
        0xb0, b'\0',
        // out %al, (%dx)
        0xee,
        // hlt
        0xf4,
    ];
    //let kvm = Kvm::new()?;
    let kvm = open()?;
    let vm = create_vm(&kvm)?;

    let source_address = unsafe {
        mmap(
            null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };

    let region = kvm_userspace_memory_region {
        slot: 0,
        flags: 0,
        guest_phys_addr: GUEST_PHYS_ADDR,
        memory_size: size as u64,
        userspace_addr: source_address as u64,
    };

    unsafe {
        vm.set_user_memory_region(region)?;
        std::ptr::copy(CODE.as_ptr(), source_address as *mut u8, 12);
    }

    let vcpu = vm.create_vcpu(0)?;

    let mut sregs = vcpu.get_sregs()?;
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    vcpu.set_sregs(&sregs)?;

    let mut regs = get_registers(&vcpu)?;

    regs.rax = 2;
    regs.rbx = 2;
    regs.rip = GUEST_PHYS_ADDR;
    regs.rflags = 0x2;

    set_registers(&vcpu, &regs)?;

    {
        // first run should be the first IO_OUT
        let run_res = run_vcpu(&vcpu)?;
        assert_eq!(run_res.message_type, KvmRunMessageType::IOOut);
        assert_eq!('4' as u64, run_res.rax);
        assert_eq!(0x3f8, run_res.port_number);
        let regs_after = get_registers(&vcpu)?;
        assert_eq!(run_res.rip, regs_after.rip);
    }
    {
        // second run should be the second IO_OUT
        let run_res = run_vcpu(&vcpu)?;
        assert_eq!(run_res.message_type, KvmRunMessageType::IOOut);
        assert_eq!(run_res.rax, 0);
        assert_eq!(run_res.port_number, 0x3f8);
    }
    {
        // third run should be the HLT
        let run_res = run_vcpu(&vcpu)?;
        assert_eq!(run_res.message_type, KvmRunMessageType::Halt);
    }

    unsafe {
        munmap(source_address, size);
    }

    Ok(())
}

/// Return `Ok(())` if the KVM API is available, or `Err` otherwise
pub fn is_present() -> Result<()> {
    let kvm = Kvm::new()?;
    let ver = kvm.get_api_version();
    if -1 == ver {
        bail!("KVM_GET_API_VERSION returned -1");
    } else if ver != 12 {
        bail!("KVM_GET_API_VERSION returned {}, expected 12", ver);
    }
    let cap_user_mem = kvm.check_extension(UserMemory);
    if !cap_user_mem {
        bail!("KVM_CAP_USER_MEMORY not supported");
    }
    Ok(())
}

/// Check if KVM exists on the machine and, if so, open the file
/// descriptor and return a reference to it. Returns `Err` if there
/// were any issues during this process.

pub fn open() -> Result<Kvm> {
    match is_present() {
        Ok(_) => Kvm::new().map_err(|e| anyhow!("Failed to open KVM: {}", e)),
        Err(_) => bail!("KVM is not present"),
    }
}

/// Create a new VM using the given `kvm` handle.
///
/// Returns `Ok` if the creation was successful, `Err` otherwise.
pub fn create_vm(kvm: &Kvm) -> Result<VmFd> {
    kvm.create_vm().map_err(|e| anyhow!(e))
}

/// Create a new virtual CPU from the given `vmfd`
pub fn create_vcpu(vmfd: &VmFd) -> Result<VcpuFd> {
    vmfd.create_vcpu(0).map_err(|e| anyhow!(e))
}

/// Get the registers from the vcpu referenced by `vcpu_fd`.
pub fn get_registers(vcpu_fd: &VcpuFd) -> Result<Regs> {
    vcpu_fd
        .get_regs()
        .map(|r| Regs::from(&r))
        .map_err(|e| anyhow!(e))
}

/// Set the given registers `regs` on the vcpu referenced by `vcpu_fd`.
///
/// Return `Ok(())` if the set operation succeeded, or an `Err` if it
/// failed.
pub fn set_registers(vcpu_fd: &VcpuFd, regs: &Regs) -> Result<()> {
    let native_regs = kvm_bindings::kvm_regs::from(regs);
    vcpu_fd.set_regs(&native_regs).map_err(|e| anyhow!(e))
}

/// Run the vcpu referenced by `vcpu_fd` until it exits, and return
/// a `kvm_run_message` indicating what happened.
pub fn run_vcpu(vcpu_fd: &VcpuFd) -> Result<KvmRunMessage> {
    match (vcpu_fd).run() {
        Ok(vcpu_exit) => {
            let port_number = get_port_num(&vcpu_exit).unwrap_or(0);
            let rax = get_rax(vcpu_fd).unwrap_or(0);
            let rip = get_rip(vcpu_fd).unwrap_or(0);
            let message_type = KvmRunMessageType::try_from(vcpu_exit)?;
            Ok(KvmRunMessage {
                message_type,
                rax,
                rip,
                port_number,
            })
        }
        Err(e) => bail!(e),
    }
}

/// A description of the results of a KVM vpu execution
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct KvmRunMessage {
    /// The exit reason of the vCPU. Will be one
    /// of the KvmMessageType constants.
    pub message_type: KvmRunMessageType,
    /// The value of the RAX register.
    pub rax: u64,
    /// The value of the RIP register.
    pub rip: u64,
    /// The port number when the reason is
    /// KVM_MESSAGE_TYPE_X64_IO_OUT. Otherwise this is set to 0
    pub port_number: u16,
}

/// The type of the output from a KVM vCPU
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum KvmRunMessageType {
    /// IO Output
    IOOut,
    /// Halt
    Halt,
}

impl<'a> TryFrom<VcpuExit<'a>> for KvmRunMessageType {
    type Error = anyhow::Error;
    fn try_from(e: VcpuExit) -> Result<Self> {
        match e {
            VcpuExit::Hlt => Ok(KvmRunMessageType::Halt),
            VcpuExit::IoOut(_, _) => Ok(KvmRunMessageType::IOOut),
            VcpuExit::InternalError => bail!("KVM internal error"),
            default => bail!("unsupported message type {:?}", default),
        }
    }
}

fn get_port_num(vcpu_exit: &VcpuExit) -> Result<u16> {
    match vcpu_exit {
        VcpuExit::IoOut(addr, _) => Ok(*addr as u16),
        _ => bail!("no port num for VcpuExit {:?}", vcpu_exit),
    }
}

fn get_rax(vcpu_fd: &VcpuFd) -> Result<u64> {
    vcpu_fd.get_regs().map(|r| r.rax).map_err(|e| anyhow!(e))
}

fn get_rip(vcpu_fd: &VcpuFd) -> Result<u64> {
    vcpu_fd.get_regs().map(|r| r.rip).map_err(|e| anyhow!(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_kvm() {
        assert!(run().is_ok());
    }
}
