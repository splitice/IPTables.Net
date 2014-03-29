using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.Adapter.Client.Helper;

namespace IPTables.Net.Tests.MockSystem.IpTablesRestore
{
    class MockIpTablesRestoreAdapterClient: IPTablesRestoreAdapterClient
    {
        private readonly MemoryStream _output = new MemoryStream();

        public MockIpTablesRestoreAdapterClient(IpTablesSystem system, string iptablesRestoreBinary = "iptables-restore") : base(system, iptablesRestoreBinary)
        {
        }

        public override void EndTransactionCommit()
        {
            StreamWriter sw = new StreamWriter(_output);
            _builder.WriteOutput(sw);
            sw.Flush();
        }

        public IEnumerable<String> GetOutput()
        {
            String output = System.Text.Encoding.ASCII.GetString(_output.ToArray());
            _output.SetLength(0);
            return output.Split(new char[] {'\n'}).Select((a)=>a.TrimEnd(new char[]{'\r'})).Where((a)=>a.Length != 0);
        }
    }
}
