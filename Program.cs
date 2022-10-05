using System.Runtime.InteropServices;

namespace kvmtest
{

    public static class Program
    {
        static int kvm = -1;
        static IntPtr pRun = IntPtr.Zero;
        static int vcpufd = -1;
        static void Main(string[] args)
        {
            if (!LinuxKVM.IsHypervisorPresent())
            {
                Console.WriteLine("KVM Not Present or accessible");
                return;
            }

            ulong size = 0x1000;
            const ulong guest_phys_addr = 0x1000;

            var sourceAddress = NativeMemory.mmap(IntPtr.Zero, size, NativeMemory.PROT_READ | NativeMemory.PROT_WRITE | NativeMemory.PROT_EXEC, NativeMemory.MAP_SHARED | NativeMemory.MAP_ANONYMOUS, -1, 0);

            if (sourceAddress == IntPtr.Zero)
            {
                Console.WriteLine("Failed to allocate memory");
                return;
            }

            byte[] code = new byte[12] { 0xba, 0xf8, 0x03, 0x00, 0xd8, 0x04, 0x00, 0xee, 0xb0, 0x00, 0xee, 0xf4 };
            Marshal.Copy(code, 0, sourceAddress, code.Length);

            if (-1 == (kvm = LinuxKVM.open("/dev/kvm", LinuxKVM.O_RDWR | LinuxKVM.O_CLOEXEC)))
            {
                Console.WriteLine("Unable to open '/dev/kvm'");
                return;
            }


            int vmfd = LinuxKVM.ioctl(kvm, LinuxKVM.KVM_CREATE_VM, 0);
            if (-1 == vmfd)
            {
                Console.WriteLine("KVM_CREATE_VM returned -1");
                return;
            }

            var region = new LinuxKVM.kvm_userspace_memory_region() { slot = 0, guest_phys_addr = guest_phys_addr, memory_size = size, userspace_addr = (ulong)sourceAddress.ToInt64() };
            int ret = LinuxKVM.ioctl(vmfd, LinuxKVM.KVM_SET_USER_MEMORY_REGION, ref region);
            if (-1 == ret)
            {
                Console.WriteLine("KVM_SET_USER_MEMORY_REGION returned -1");
                return;
            }

            vcpufd = LinuxKVM.ioctl(vmfd, LinuxKVM.KVM_CREATE_VCPU, 0);
            if (-1 == vcpufd)
            {
                Console.WriteLine("VM_CREATE_VCPU returned -1");
                return;
            }

            int mmap_size = LinuxKVM.ioctl(kvm, LinuxKVM.KVM_GET_VCPU_MMAP_SIZE, 0);

            pRun = NativeMemory.mmap(IntPtr.Zero, (UInt64)mmap_size, NativeMemory.PROT_READ | NativeMemory.PROT_WRITE, NativeMemory.MAP_SHARED, vcpufd, 0);

            LinuxKVM.kvm_sregs sregs = new();
            ret = LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_GET_SREGS, ref sregs);
            if (-1 == ret)
            {
                Console.WriteLine("KVM_GET_SREGS returned -1");
                return;
            }

            sregs.cs.Base = 0;
            sregs.cs.selector = 0;

            ret = LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_SET_SREGS, ref sregs);
            if (-1 == ret)
            {
                Console.WriteLine("KVM_SET_SREGS returned -1");
                return;
            }

            LinuxKVM.kvm_regs regs = new()
            {
                rip = guest_phys_addr,
                rax = (ulong)2,
                rbx = (ulong)2,
                rflags = 0x0002,
            };
            ret = LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_SET_REGS, ref regs);
            if (-1 == ret)
            {
                Console.WriteLine("KVM_SET_REGS returned -1");
                return;
            }

            ExecuteUntilHalt();

            Console.WriteLine("Done");

        }
        static void ExecuteUntilHalt()
        {
            int count = 0;
            while (true)
            {
                int ret = LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_RUN, 0);
                if (-1 == ret)
                {
                    Console.WriteLine("KVM_RUN returned -1");
                    return;
                }
                var run = Marshal.PtrToStructure<LinuxKVM.kvm_run>(pRun);
                switch (run.exit_reason)
                {
                    case LinuxKVM.KVM_EXIT_HLT:
                        return;
                    case LinuxKVM.KVM_EXIT_IO:
                        // Save rip, call HandleOutb, then restore rip
                        LinuxKVM.kvm_regs regs = new();
                        ret = LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_GET_REGS, ref regs);
                        if (-1 == ret)
                        {
                            Console.WriteLine("KVM_GET_REGS returned -1");
                            return;
                        }
                        UInt64 ripOrig = regs.rip;
                        count++;
                        HandleOutb(run.port, Marshal.ReadByte(pRun, (int)run.data_offset), count);

                        // Restore rip
                        ret = LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_GET_REGS, ref regs);
                        if (-1 == ret)
                        {
                            Console.WriteLine("KVM_GET_REGS returned -1");
                            return;
                        }
                        regs.rip = ripOrig;
                        ret = LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_SET_REGS, ref regs);
                        if (-1 == ret)
                        {
                            Console.WriteLine("KVM_SET_REGS returned -1");
                            return;
                        }
                        break;
                    default:
                        Console.WriteLine($"Unexpected exit_reason = {run.exit_reason}");
                        return;
                }
            }
        }

        static void HandleOutb(UInt16 port, byte value, int count)
        {
            if (count < 3)
            {
                Console.WriteLine($"Port = {port:X4}, Value = {value}");
            }
            else
            {
                Console.WriteLine("Unexpected EXIT_IO");
            }

        }
    }
}