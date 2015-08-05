using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.U32;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class U32ParserTests
    {
        [TestCase]
        public void U32RangeParseTest()
        {
            String str = "1:0x02";
            var range = U32Range.Parse(ref str);
            Assert.AreEqual(range.From, 1);
            Assert.AreEqual(range.To, 2);
        }

        [TestCase]
        public void U32RangeParseSingleTest()
        {
            String str = "1";
            var range = U32Range.Parse(ref str);
            Assert.AreEqual(range.From, 1);
            Assert.AreEqual(range.To, 1);
        }

        [TestCase]
        public void U32LocationTest()
        {
            String str = "1>>2";
            var range = U32Location.Parse(ref str);

            Assert.AreEqual(range.Location, 1);
            Assert.AreEqual(range.Op, U32Location.Operator.Right);
            Assert.AreEqual(range.Number, 2);
        }
    }
}
