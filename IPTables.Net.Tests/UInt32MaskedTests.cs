using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IPTables.Net.Iptables.DataTypes;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    public class UInt32MaskedTests
    {
        [Test]
        public void TestComparison()
        {
            Assert.AreEqual(new UInt32Masked(0, 1), new UInt32Masked(0, 1));
            Assert.AreEqual(new UInt32Masked(1, 1), new UInt32Masked(1, 1));
        }
    }
}
