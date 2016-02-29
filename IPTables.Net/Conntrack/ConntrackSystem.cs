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
        private Dictionary<String, int> _constants = new Dictionary<string, int>();

        public int GetConstant(String key)
        {
            int value;
            if (!_constants.TryGetValue(key, out value))
            {
                value = ConntrackHelper.cr_constant(key);
                _constants.Add(key, value);
            }
            return value;
        }

        public void Restore(bool expectationsTable, byte[] data)
        {
            ConntrackHelper.restore_nf_cts(expectationsTable, data, data.Length);
        }

        public void Dump(bool expectationTable, Action<byte[]> cb, ConntrackQueryFilter[] qf = null, AddressFamily addressFamily = AddressFamily.Unspecified)
        {
            lock (_queryLock)
            {
                if (qf != null || addressFamily != AddressFamily.Unspecified)
                {
                    ConntrackHelper.conditional_init((int)addressFamily, qf, qf.Length);
                }

                try
                {
                    byte[] buffer = new byte[1];
                    ConntrackHelper.CrImg img = new ConntrackHelper.CrImg();
                    ConntrackHelper.dump_nf_cts(expectationTable, ref img);
                    try
                    {
                        IntPtr ptr = img.CrNode;
                        while (ptr != IntPtr.Zero)
                        {
                            int crsize = ConntrackHelper.cr_length(ptr);
                            IntPtr newPtr = Marshal.ReadIntPtr(ptr);
                            crsize -= IntPtr.Size;
                            ptr = new IntPtr((int) ptr + IntPtr.Size);
                            if (buffer.Length != crsize)
                            {
                                buffer = new byte[crsize];
                            }
                            Marshal.Copy(newPtr, buffer, 0, crsize);
                            cb(buffer);
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
