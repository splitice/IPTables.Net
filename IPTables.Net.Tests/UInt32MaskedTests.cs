using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Tests
{
    public class UInt32MaskedTests
    {
        [Fact]
        public void TestComparison()
        {
            Assert.Equal(new UInt32Masked(0, 1), new UInt32Masked(0, 1));
            Assert.Equal(new UInt32Masked(1, 1), new UInt32Masked(1, 1));
        }
    }
}
