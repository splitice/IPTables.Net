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
        private static readonly object QueryLock = new object();
        private readonly ConntrackApi _native;
        public ConntrackSystem() : this(new ConntrackApi()) { }
        internal ConntrackSystem(ConntrackApi native) { _native = native; }
        private Dictionary<string, ushort> _constants = new Dictionary<string, ushort>();

        public ushort GetConstant(string key)
        {
            lock (_constants)
            {
                ushort value;
                if (!_constants.TryGetValue(key, out value))
                {
                    var v = _native.Constant(key);
                    if (v < 0 || v > ushort.MaxValue) throw new KeyNotFoundException(string.Format("Unable to lookup constant {0}", key));
                    Debug.Assert(v <= ushort.MaxValue);
                    value = (ushort) v;
                    _constants.Add(key, value);
                }

                return value;
            }
        }

        public bool ExtractField<T>(ConntrackQueryFilter[] qf, byte[] conn, out T output) where T : struct
        {
            ArgumentNullException.ThrowIfNull(qf);
            ArgumentNullException.ThrowIfNull(conn);
            if (conn.Length < 20 || BitConverter.ToUInt32(conn, 0) < 20 || BitConverter.ToUInt32(conn, 0) > conn.Length)
                throw new ArgumentException("Invalid conntrack record length", nameof(conn));
            var size = Marshal.SizeOf(typeof(T));
            var handle = Marshal.AllocHGlobal(size);
            if (handle == IntPtr.Zero) throw new IpTablesNetException("Unable to allocate memory for Conntrack field");

            try
            {
                var ret = _native.Extract(qf, conn, handle, size);
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
            ArgumentNullException.ThrowIfNull(data);
            lock (QueryLock)
            {
                var useRestoreMark = restoreMark != 0 || restoreMarkMask != 0;
                try
                {
                    if (useRestoreMark) _native.Mark(restoreMark, restoreMarkMask);
                    var result = _native.Restore(expectationsTable, data);
                    if (result < 0) throw new IpTablesNetException($"Unable to restore conntrack records: errno {-result}");
                    return result;
                }
                finally { if (useRestoreMark) _native.ClearMark(); }
            }
        }

        public void Dump(bool expectationTable, Action<byte[]> cb, ConntrackQueryFilter[] qf = null,
            AddressFamily addressFamily = AddressFamily.Unspecified)
        {
            ArgumentNullException.ThrowIfNull(cb);
            int family = addressFamily switch
            {
                AddressFamily.Unspecified => 0,
                AddressFamily.InterNetwork => 2,
                AddressFamily.InterNetworkV6 => 10,
                _ => throw new ArgumentOutOfRangeException(nameof(addressFamily))
            };
            lock (QueryLock)
            {
                var img = new ConntrackHelper.CrImg();
                try
                {
                    _native.Filter(family, qf);
                    var result = _native.Dump(expectationTable, ref img);
                    if (result < 0) throw new IpTablesNetException($"Unable to dump conntrack records: errno {-result}");
                    var ptr = img.CrNode;
                    while (ptr != IntPtr.Zero)
                    {
                        var size = _native.Length(ptr) - IntPtr.Size;
                        if (size < 20) throw new IpTablesNetException("Invalid conntrack record length");
                        var buffer = new byte[size];
                        Marshal.Copy(IntPtr.Add(ptr, IntPtr.Size), buffer, 0, size);
                        cb(buffer);
                        ptr = Marshal.ReadIntPtr(ptr);
                    }
                }
                finally
                {
                    try { if (img.CrNode != IntPtr.Zero) _native.Free(ref img); }
                    finally { _native.ClearFilter(); }
                }
            }
        }
    }
}
