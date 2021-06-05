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
        private Dictionary<string, ushort> _constants = new Dictionary<string, ushort>();

        public ushort GetConstant(string key)
        {
            lock (_constants)
            {
                ushort value;
                if (!_constants.TryGetValue(key, out value))
                {
                    var v = ConntrackHelper.cr_constant(key);
                    if (v == -1) throw new KeyNotFoundException(string.Format("Unable to lookup constant {0}", key));
                    Debug.Assert(v <= ushort.MaxValue);
                    value = (ushort) v;
                    _constants.Add(key, value);
                }

                return value;
            }
        }

        public bool ExtractField<T>(ConntrackQueryFilter[] qf, byte[] conn, out T output) where T : struct
        {
            var size = Marshal.SizeOf(typeof(T));
            var handle = Marshal.AllocHGlobal(size);
            if (handle == IntPtr.Zero) throw new IpTablesNetException("Unable to allocate memory for Conntrack field");

            try
            {
                var ret = ConntrackHelper.cr_extract_field(qf, qf.Length, conn, handle, size);
                if (ret)
                {
                    var obj = Marshal.PtrToStructure(handle, typeof(T));
                    if (obj == null) throw new IpTablesNetException("Unable to marshal type");
                    output = (T) obj;
                }
                else
                {
                    output = default;
                }

                return ret;
            }
            finally
            {
                Marshal.FreeHGlobal(handle);
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
        public int Restore(bool expectationsTable, byte[] data, uint restoreMark = 0, uint restoreMarkMask = 0)
        {
            var useRestoreMark = restoreMark != 0 || restoreMarkMask != 0;
            if (useRestoreMark) ConntrackHelper.restore_mark_init(restoreMark, restoreMarkMask);
            var errorCode = ConntrackHelper.restore_nf_cts(expectationsTable, data, data.Length);
            if (errorCode < 0)
                throw new IpTablesNetException(string.Format("An error occured while loading NFCTs with the errno: {0}",
                    -errorCode));
            if (useRestoreMark) ConntrackHelper.restore_mark_free();

            return errorCode;
        }

        public void Dump(bool expectationTable, Action<byte[]> cb, ConntrackQueryFilter[] qf = null,
            AddressFamily addressFamily = AddressFamily.Unspecified)
        {
            lock (_queryLock)
            {
                ConntrackHelper.conditional_init((int) addressFamily, qf, qf == null ? 0 : qf.Length);

                try
                {
                    var buffer = new byte[1];
                    var img = new ConntrackHelper.CrImg();
                    Debug.Assert(img.CrNode == IntPtr.Zero);

                    ConntrackHelper.dump_nf_cts(expectationTable, ref img);

                    try
                    {
                        var ptr = img.CrNode;
                        while (ptr != IntPtr.Zero)
                        {
                            var crsize = ConntrackHelper.cr_length(ptr);
                            var newPtr = Marshal.ReadIntPtr(ptr);

                            crsize -= IntPtr.Size;
                            Debug.Assert(crsize > 0);
                            if (buffer.Length != crsize) buffer = new byte[crsize];

                            Marshal.Copy(new IntPtr((long) ptr + IntPtr.Size), buffer, 0, crsize);
                            cb(buffer);

                            ptr = newPtr;
                        }
                    }
                    finally
                    {
                        if (img.CrNode != IntPtr.Zero) ConntrackHelper.cr_free(img);
                    }
                }
                finally
                {
                    if (qf != null || addressFamily != AddressFamily.Unspecified) ConntrackHelper.conditional_free();
                }
            }
        }
    }
}