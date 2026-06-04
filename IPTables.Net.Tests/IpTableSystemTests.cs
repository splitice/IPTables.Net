using IPTables.Net.Exceptions;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using SystemInteract.Local;

namespace IPTables.Net.Tests
{
    public class IpTableSystemTests
    {
        private const int IP_VERSION = 4;

        [Fact]
        public void TestGetRules()
        {
            TestEnvironment.RequireLinuxSystemTests();

            var system = new IpTablesSystem(system: new LocalFactory(), tableAdapter: new IPTablesBinaryAdapter());

            // Invalid table cause exception
            Assert.Throws<IpTablesNetException>(() => system.GetRules("_invalidTableName", IP_VERSION));
        }
    }
}
