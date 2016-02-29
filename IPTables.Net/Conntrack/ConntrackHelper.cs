using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace IPTables.Net.Conntrack
{
    class ConntrackHelper
    {
        public const String Helper = "libipthelper.so";


        internal struct CrImg
        {
            public IntPtr CrNode;
        }

        [DllImport(Helper)]
        public static extern int dump_nf_cts(bool expectations, out CrImg img);

        [DllImport(Helper)]
        public static extern int restore_nf_cts(bool expectations, byte[] data, Int32 data_length);

        [DllImport(Helper)]
        public static extern UInt16 cr_constant(string constant);

        [DllImport(Helper)]
        public static extern int cr_free(CrImg img);

        [DllImport(Helper)]
        public static extern int cr_length(IntPtr node);

        [DllImport(Helper)]
        public static extern int conditional_free();

        [DllImport(Helper)]
        public static extern int conditional_init(Int32 address_family, ConntrackQueryFilter[] qf, int qfLength);
    }
}
