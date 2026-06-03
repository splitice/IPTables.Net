using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.U32;

namespace IPTables.Net.Tests
{
    public class U32ParserTests
    {
        [Fact]
        public void U32RangeParseTest()
        {
            String str = "1:0x02";
            var range = U32Range.Parse(ref str);
            Assert.Equal((uint)1, range.From);
            Assert.Equal((uint)2, range.To);
        }

        [Fact]
        public void U32RangeParseSingleTest()
        {
            String str = "1";
            var range = U32Range.Parse(ref str);
            Assert.Equal((uint)1, range.From);
            Assert.Equal((uint)1, range.To);
        }

        [Fact]
        public void U32LocationTest()
        {
            String str = "1>>2";
            var range = U32Location.Parse(ref str);

            Assert.Equal("1", range.Location.ToString());
            Assert.Equal(U32Location.Operator.Right, range.Op);
            Assert.Equal((uint)2, range.Number);
        }

        [Fact]
        public void U32LocationTest2()
        {
            String str = "1@0";
            var range = U32Location.Parse(ref str);

            Assert.Equal("1", range.Location.ToString());
            Assert.Equal(U32Location.Operator.Move, range.Op);
        }


        [Fact]
        public void U32FullTest1()
        {
            String str = "0 & 0xFFFF = 0x100:0xFFFF";
            var range = U32Expression.Parse(str);
            Assert.Equal(range, U32Expression.Parse(range.ToString()));
        }

        [Fact]
        public void U32FullTest2()
        {
            String str = "6 & 0xFF = 1 && 4 & 0x3FFF = 0 &&  0 >> 22 & 0x3C @ 0 >> 24 = 0";
            var range = U32Expression.Parse(str);
            Assert.Equal(range, U32Expression.Parse(range.ToString()));
        }

        [Fact]
        public void U32FullTest3()
        {
            String str = "26 & 0x3C @ 8 = 1,2,5,8";
            var range = U32Expression.Parse(str);
            Assert.Equal(range, U32Expression.Parse(range.ToString()));
        }

        [Fact]
        public void U32FullTest4()
        {
            String str = "6&0xFF=0x6&&0>>22&0x3C@12&0xFFFF=0";
            var range = U32Expression.Parse(str);
            Assert.Equal(range, U32Expression.Parse(range.ToString()));
        }
    }
}
