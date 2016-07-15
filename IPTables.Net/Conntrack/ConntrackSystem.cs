using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using IPTables.Net.Exceptions;

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
                    int v = ConntrackHelper.cr_constant(key);
                    if (v == -1)
                    {
                        throw new KeyNotFoundException(String.Format("Unable to lookup constant {0}", key));
                    }
                    Debug.Assert(v <= UInt16.MaxValue);
                    value = (UInt16)v;
                    _constants.Add(key, value);
                }
                return value;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="expectationsTable"></param>
        /// <param name="data"></param>
        /// <param name="restoreMark"></param>
        /// <param name="restoreMarkMask"></param>
        /// <returns>remaining unprocessed data</returns>
        public int Restore(bool expectationsTable, byte[] data, UInt32 restoreMark = 0, UInt32 restoreMarkMask = 0)
        {
            bool useRestoreMark = restoreMark != 0 || restoreMarkMask != 0;
            if (useRestoreMark)
            {
                ConntrackHelper.restore_mark_init(restoreMark,restoreMarkMask);
            }
            int errorCode = ConntrackHelper.restore_nf_cts(expectationsTable, data, data.Length);
            if (errorCode < 0)
            {
                throw new IpTablesNetException(String.Format("An error occured while loading NFCTs with the errno: {0}", -errorCode));
            }
            if (useRestoreMark)
            {
                ConntrackHelper.restore_mark_free();
            }

            return errorCode;
        }

        public void Dump(bool expectationTable, Action<byte[]> cb, ConntrackQueryFilter[] qf = null, AddressFamily addressFamily = AddressFamily.Unspecified)
        {
            lock (_queryLock)
            {
                ConntrackHelper.conditional_init((int)addressFamily, qf, qf == null ? 0 : qf.Length);

                try
                {
                    byte[] buffer = new byte[1];
                    ConntrackHelper.CrImg img = new ConntrackHelper.CrImg();
                    Debug.Assert(img.CrNode == IntPtr.Zero);
                    ConntrackHelper.dump_nf_cts(expectationTable, ref img);
                    try
                    {
                        IntPtr ptr = img.CrNode;
                        while (ptr != IntPtr.Zero)
                        {
                            int crsize = ConntrackHelper.cr_length(ptr);
                            IntPtr newPtr = Marshal.ReadIntPtr(ptr);
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
                        if (img.CrNode != IntPtr.Zero)
                        {
                            ConntrackHelper.cr_free(img);
                        }
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
