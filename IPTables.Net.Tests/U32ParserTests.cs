using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.U32;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class U32ParserTests
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

            Assert.AreEqual(range.Location.ToString(), "1");
            Assert.AreEqual(range.Op, U32Location.Operator.Right);
            Assert.AreEqual(range.Number, 2);
        }

        [TestCase]
        public void U32LocationTest2()
        {
            String str = "1@0";
            var range = U32Location.Parse(ref str);

            Assert.AreEqual("1", range.Location.ToString());
            Assert.AreEqual(range.Op, U32Location.Operator.Move);
        }


        [TestCase]
        public void U32FullTest1()
        {
            String str = "0 & 0xFFFF = 0x100:0xFFFF";
            var range = U32Expression.Parse(str);
            Assert.AreEqual(range, U32Expression.Parse(range.ToString()));
        }

        [TestCase]
        public void U32FullTest2()
        {
            String str = "6 & 0xFF = 1 && 4 & 0x3FFF = 0 &&  0 >> 22 & 0x3C @ 0 >> 24 = 0";
            var range = U32Expression.Parse(str);
            Assert.AreEqual(range, U32Expression.Parse(range.ToString()));
        }

        [TestCase]
        public void U32FullTest3()
        {
            String str = "26 & 0x3C @ 8 = 1,2,5,8";
            var range = U32Expression.Parse(str);
            Assert.AreEqual(range, U32Expression.Parse(range.ToString()));
        }

        [TestCase]
        public void U32FullTest4()
        {
            String str = "6&0xFF=0x6&&0>>22&0x3C@12&0xFFFF=0";
            var range = U32Expression.Parse(str);
            Assert.AreEqual(range, U32Expression.Parse(range.ToString()));
        }
    }
}
