using System;
namespace IPTables.Net.Conntrack
{
    internal class ConntrackApi
    {
        internal virtual int Constant(string key) => ConntrackHelper.cr_constant(key);
        internal virtual void Mark(uint mark, uint mask) => ConntrackHelper.restore_mark_init(mark, mask);
        internal virtual void ClearMark() => ConntrackHelper.restore_mark_free();
        internal virtual int Restore(bool expectations, byte[] data) => ConntrackHelper.restore_nf_cts(expectations, data, data.Length);
        internal virtual void Filter(int family, ConntrackQueryFilter[] filters) => ConntrackHelper.conditional_init(family, filters, filters?.Length ?? 0);
        internal virtual void ClearFilter() => ConntrackHelper.conditional_free();
        internal virtual int Dump(bool expectations, ref ConntrackHelper.CrImg image) => ConntrackHelper.dump_nf_cts(expectations, ref image);
        internal virtual int Length(IntPtr node) => ConntrackHelper.cr_length(node);
        internal virtual void Free(ref ConntrackHelper.CrImg image) => ConntrackHelper.cr_free(ref image);
        internal virtual bool Extract(ConntrackQueryFilter[] filters, byte[] data, IntPtr output, int size) => ConntrackHelper.cr_extract_field(filters, filters.Length, data, output, size);
    }
}
