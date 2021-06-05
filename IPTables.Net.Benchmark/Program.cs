using System;
using System.Diagnostics;
using IPTables.Net.Iptables;

namespace IPTables.Net.Benchmark
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            IpTablesChainSet cs = new IpTablesChainSet(4);
            for (int i = 0; i < 10000; i++)
            {
                IpTablesRule.Parse(String.Format("-A {0} -t raw -d 1.1.1.1 -m comment --comment 'test' -j ACCEPT", i), null, cs);
            }
            sw.Stop();
            Console.WriteLine("Parsed in {0}", sw.Elapsed);

            sw.Reset();

            var r = IpTablesRule.Parse("-A PREROUTING -t raw -d 1.1.1.1 -m comment --comment 'test' -j ACCEPT", null, cs);
            sw.Start();
            for (int i = 0; i < 100000; i++)
            {
                r.GetActionCommand();
            }
            sw.Stop();
            Console.WriteLine("Rendered in {0}", sw.Elapsed);


        }
    }
}
