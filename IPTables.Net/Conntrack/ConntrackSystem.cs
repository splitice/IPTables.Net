using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace IPTables.Net.Conntrack
{
    public class ConntrackSystem
    {
        private object _queryLock = new object();
        private Dictionary<String, UInt16> _constants = new Dictionary<string, UInt16>();

        public UInt16 GetConstant(String key)
        {
            lock (_constants)
            {
                UInt16 value;
                if (!_constants.TryGetValue(key, out value))
                {
                    value = ConntrackHelper.cr_constant(key);
                    _constants.Add(key, value);
                }
                return value;
            }
        }

        public void Restore(bool expectationsTable, byte[] data)
        {
            ConntrackHelper.restore_nf_cts(expectationsTable, data, data.Length);
        }

        public void Dump(bool expectationTable, Action<byte[]> cb, ConntrackQueryFilter[] qf = null, AddressFamily addressFamily = AddressFamily.Unspecified)
        {
            lock (_queryLock)
            {
                ConntrackHelper.conditional_init((int)addressFamily, qf, qf == null ? 0 : qf.Length);

                try
                {
                    byte[] buffer = new byte[1];
                    ConntrackHelper.CrImg img;
                    ConntrackHelper.dump_nf_cts(expectationTable, out img);
                    Console.WriteLine("dump done");
                    try
                    {
                        IntPtr ptr = img.CrNode;
                        while (ptr != IntPtr.Zero)
                        {
                            int crsize = ConntrackHelper.cr_length(ptr);
                            Console.WriteLine("len: " + crsize);
                            IntPtr newPtr = Marshal.ReadIntPtr(ptr);
                            Console.WriteLine("ptr: "+ptr+" newPtr: " + newPtr);
                            crsize -= IntPtr.Size;
                            if (buffer.Length != crsize)
                            {
                                buffer = new byte[crsize];
                            }
                            Marshal.Copy(new IntPtr((long) ptr + IntPtr.Size), buffer, 0, crsize);
                            cb(buffer);
                            ptr = newPtr;
                        }
                    }
                    finally
                    {
                        ConntrackHelper.cr_free(img);
                    }
                }
                finally
                {
                    if (qf != null || addressFamily != AddressFamily.Unspecified)
                    {
                        ConntrackHelper.conditional_free();
                    }
                }
            }
        }
    }
}
