using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SystemInteract.Local;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class IpTableSystemTests
    {
        [SetUp]
        public void Initialize()
        {
            if (IsLinux)
            {
                if (Environment.GetEnvironmentVariable("SKIP_SYSTEM_TESTS") != "1")
                {
                    _system = new IpTablesSystem(system: new LocalFactory(), tableAdapter: new IPTablesBinaryAdapter());
                }
            }
        }

        [Test]
        public void TestGetRules()
        {
            if (IsLinux)
            {
                if (Environment.GetEnvironmentVariable("SKIP_SYSTEM_TESTS") == "1")
                {
                    Assert.Ignore();
                }

                // Invalid table cause exception
                Assert.Throws<ArgumentException>(() => _system.GetRules("INPUT", IP_VERSION));
            }
        }

        public static bool IsLinux
        {
            get
            {
                int p = (int)Environment.OSVersion.Platform;
                return (p == 4) || (p == 6) || (p == 128);
            }
        }

        private IpTablesSystem _system;
        private const int IP_VERSION = 4;
    }
}
