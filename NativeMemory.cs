using System;
using System.Runtime.InteropServices;

namespace kvmtest
{
    static class NativeMemory
    {

        //////////////////////////////////////////////////////////////////////
        // Linux memory management functions

        public const int PROT_READ = 0x1; /* page can be read */
        public const int PROT_WRITE = 0x2; /* page can be written */
        public const int PROT_EXEC = 0x4; /* page can be executed */
        public const int PROT_SEM = 0x8; /* page may be used for atomic ops */
        public const int PROT_NONE = 0x0; /* page can not be accessed */

        public const int MAP_SHARED = 0x01; /* Share changes */
        public const int MAP_PRIVATE = 0x02; /* Changes are private */
        public const int MAP_ANONYMOUS = 0x20;/* don't use a file */

        [DllImport("libc", SetLastError = true)]
        public static extern IntPtr mmap(IntPtr addr, UInt64 Length, int prot, int flags, int fd, UInt64 offset);

        [DllImport("libc", SetLastError = true)]
        public static extern IntPtr munmap(IntPtr addr, UInt64 Length);


    }
}
