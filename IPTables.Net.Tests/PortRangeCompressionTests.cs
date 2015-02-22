using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    public class PortRangeCompressionTests
    {
        [TestCase]
        public void TestCompress1()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80) };

            List<PortOrRange> actual = PortRangeCompression.CompressRanges(input);

            CollectionAssert.AreEqual(output,actual);
        }

        [TestCase]
        public void TestCompress2()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(82) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(82) };

            List<PortOrRange> actual = PortRangeCompression.CompressRanges(input);

            CollectionAssert.AreEqual(output, actual);
        }

        [TestCase]
        public void TestCompress3()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(82, 84) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(82, 84) };

            List<PortOrRange> actual = PortRangeCompression.CompressRanges(input);

            CollectionAssert.AreEqual(output, actual);
        }

        [TestCase]
        public void TestCompress4()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(81, 84) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80, 84) };

            List<PortOrRange> actual = PortRangeCompression.CompressRanges(input);

            CollectionAssert.AreEqual(output, actual);
        }

        [TestCase]
        public void TestCompress5()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(81) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80, 81) };

            List<PortOrRange> actual = PortRangeCompression.CompressRanges(input);

            CollectionAssert.AreEqual(output, actual);
        }

        [TestCase]
        public void TestCompress6()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(81), new PortOrRange(82, 83), new PortOrRange(85), new PortOrRange(86,90) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80, 83), new PortOrRange(85,90) };

            List<PortOrRange> actual = PortRangeCompression.CompressRanges(input);

            CollectionAssert.AreEqual(output, actual);
        }
    }
}
