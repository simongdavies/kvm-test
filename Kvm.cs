using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace kvmtest
{
    static class LinuxKVM
    {
        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, UInt64 request, [In][Out] ref kvm_sregs sregs);
        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, UInt64 request, [In][Out] ref kvm_regs regs);
        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, UInt64 request, [In][Out] ref kvm_userspace_memory_region region);

        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, UInt64 request, UInt64 arg1);


        [DllImport("libc", SetLastError = true)]
        public static extern int open(string path, int flags);

        [DllImport("libc", SetLastError = true)]
        public static extern int close(int fd);

        public const int O_RDWR = 2;
        public const int O_CLOEXEC = 0x80000;

        const int _IOC_READ = 2;
        const int _IOC_WRITE = 1;

        const int _IOC_NRBITS = 8;
        const int _IOC_TYPEBITS = 8;
        const int _IOC_SIZEBITS = 14;
        const int _IOC_DIRBITS = 2;

        const int _IOC_NRSHIFT = 0;
        const int _IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS;
        const int _IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS;
        const int _IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS;

        const UInt32 KVMIO = 0xAE;

        public const UInt64 KVM_GET_API_VERSION = (KVMIO << _IOC_TYPESHIFT) + (0x00 << _IOC_NRSHIFT);
        public const UInt64 KVM_CREATE_VM = (KVMIO << _IOC_TYPESHIFT) + (0x01 << _IOC_NRSHIFT);
        public const UInt64 KVM_CHECK_EXTENSION = (KVMIO << _IOC_TYPESHIFT) + (0x03 << _IOC_NRSHIFT);
        public const UInt64 KVM_GET_VCPU_MMAP_SIZE = (KVMIO << _IOC_TYPESHIFT) + (0x04 << _IOC_NRSHIFT);
        public const UInt64 KVM_CREATE_VCPU = (KVMIO << _IOC_TYPESHIFT) + (0x41 << _IOC_NRSHIFT);
        public const UInt64 KVM_RUN = (KVMIO << _IOC_TYPESHIFT) + (0x80 << _IOC_NRSHIFT);

        public static UInt64 KVM_GET_SREGS = (UInt64)((_IOC_READ << _IOC_DIRSHIFT) + (KVMIO << _IOC_TYPESHIFT) + (0x83 << _IOC_NRSHIFT) + (Marshal.SizeOf<kvm_sregs>() << _IOC_SIZESHIFT));
        public static UInt64 KVM_SET_SREGS = (UInt64)((_IOC_WRITE << _IOC_DIRSHIFT) + (KVMIO << _IOC_TYPESHIFT) + (0x84 << _IOC_NRSHIFT) + (Marshal.SizeOf<kvm_sregs>() << _IOC_SIZESHIFT));

        public static UInt64 KVM_SET_USER_MEMORY_REGION = (UInt64)((_IOC_WRITE << _IOC_DIRSHIFT) + (KVMIO << _IOC_TYPESHIFT) + (0x46 << _IOC_NRSHIFT) + (Marshal.SizeOf<kvm_userspace_memory_region>() << _IOC_SIZESHIFT));
        public static UInt64 KVM_SET_REGS = (UInt64)((_IOC_WRITE << _IOC_DIRSHIFT) + (KVMIO << _IOC_TYPESHIFT) + (0x82 << _IOC_NRSHIFT) + (Marshal.SizeOf<kvm_regs>() << _IOC_SIZESHIFT));
        public static UInt64 KVM_GET_REGS = (UInt64)((_IOC_READ  << _IOC_DIRSHIFT) + (KVMIO << _IOC_TYPESHIFT) + (0x81 << _IOC_NRSHIFT) + (Marshal.SizeOf<kvm_regs>() << _IOC_SIZESHIFT));

        const int KVM_CAP_USER_MEMORY = 3;

        public const int KVM_EXIT_IO = 2;
        public const int KVM_EXIT_HLT = 5;

        public const int KVM_EXIT_IO_IN = 0;
        public const int KVM_EXIT_IO_OUT = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct kvm_segment
        {
            public UInt64 Base;
            public UInt32 limit;
            public UInt16 selector;
            public Byte type;
            public Byte present, dpl, db, s, l, g, avl;
            public Byte unusable;
            public Byte padding;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct kvm_userspace_memory_region
        {
            public UInt32 slot;
            public UInt32 flags;
            public UInt64 guest_phys_addr;
            public UInt64 memory_size;
            public UInt64 userspace_addr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct kvm_dtable
        {
            public UInt64 Base;
            public UInt16 limit;
            public UInt16 padding1, padding2, padding3;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct kvm_sregs
        {
            public kvm_segment cs, ds, es, fs, gs, ss;
            public kvm_segment tr, ldt;
            public kvm_dtable gdt, idt;
            public UInt64 cr0, cr2, cr3, cr4, cr8;
            public UInt64 efer;
            public UInt64 apic_base;
            public UInt64 interrupt_bitmap1, interrupt_bitmap2, interrupt_bitmap3, interrupt_bitmap4; // 32 320
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct kvm_regs
        {
            public UInt64 rax, rbx, rcx, rdx;
            public UInt64 rsi, rdi, rsp, rbp;
            public UInt64 r8, r9, r10, r11;
            public UInt64 r12, r13, r14, r15;
            public UInt64 rip, rflags;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct kvm_run
        {
            public Byte request_interrupt_window;
            public Byte immediate_exit;
            public Byte padding1_1, padding1_2, padding1_3, padding1_4, padding1_5, padding1_6;

            /* out */
            public UInt32 exit_reason;
            public Byte ready_for_interrupt_injection;
            public Byte if_flag;
            public UInt16 flags;

            /* in (pre_kvm_run), out (post_kvm_run) */
            public UInt64 cr8;
            public UInt64 apic_base;

            // io
            public Byte direction;
            public Byte size; /* bytes */
            public UInt16 port;
            public UInt32 count;
            public UInt64 data_offset; /* relative to kvm_run start */
        }


        public static bool IsHypervisorPresent()
        {
            int kvm = -1;
            try
            {
                if (-1 == (kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC)))
                {
                    Console.Error.WriteLine("Unable to open '/dev/kvm'");
                    return false;
                }

                int kvmApiVersion = ioctl(kvm, KVM_GET_API_VERSION, 0);
                if (-1 == kvmApiVersion)
                {
                    Console.Error.WriteLine("KVM_GET_API_VERSION returned -1");
                    return false;
                }
                if (12 != kvmApiVersion)
                {
                    Console.WriteLine("KVM API Version was not 12 as expected");
                    return false;
                }

                int capUserMemory = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
                if (-1 == capUserMemory)
                {
                    Console.Error.WriteLine("KVM_CHECK_EXTENSION/KVM_CAP_USER_MEMORY returned -1");
                    return false;
                }
                if (0 == capUserMemory)
                {
                    Console.Error.WriteLine("KVM_CAP_USER_MEMORY not available");
                    return false;
                }
            }
            finally
            {
                if (kvm != -1)
                    close(kvm);
            }
            return true;
        }
    }
}
