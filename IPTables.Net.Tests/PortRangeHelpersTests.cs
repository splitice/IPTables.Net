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
    public class PortRangeHelpersTests
    {
        [TestCase]
        public void TestCompress1()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80) };

            List<PortOrRange> actual = PortRangeHelpers.CompressRanges(input);

            CollectionAssert.AreEqual(output,actual);
        }

        [TestCase]
        public void TestCompress2()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(82) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(82) };

            List<PortOrRange> actual = PortRangeHelpers.CompressRanges(input);

            CollectionAssert.AreEqual(output, actual);
        }

        [TestCase]
        public void TestCompress3()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(82, 84) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(82, 84) };

            List<PortOrRange> actual = PortRangeHelpers.CompressRanges(input);

            CollectionAssert.AreEqual(output, actual);
        }

        [TestCase]
        public void TestCompress4()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(81, 84) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80, 84) };

            List<PortOrRange> actual = PortRangeHelpers.CompressRanges(input);

            CollectionAssert.AreEqual(output, actual);
        }

        [TestCase]
        public void TestCompress5()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(81) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80, 81) };

            List<PortOrRange> actual = PortRangeHelpers.CompressRanges(input);

            CollectionAssert.AreEqual(output, actual);
        }

        [TestCase]
        public void TestCompress6()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(81), new PortOrRange(82, 83), new PortOrRange(85), new PortOrRange(86,90) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80, 83), new PortOrRange(85,90) };

            List<PortOrRange> actual = PortRangeHelpers.CompressRanges(input);

            CollectionAssert.AreEqual(output, actual);
        }

        [TestCase]
        public void TestCompress7()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80) };

            List<PortOrRange> actual = PortRangeHelpers.CompressRanges(input);

            CollectionAssert.AreEqual(output, actual);
        }

        [TestCase]
        public void TestCompress8()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80, 90) };
            List<PortOrRange> output = new List<PortOrRange> { new PortOrRange(80, 90) };

            List<PortOrRange> actual = PortRangeHelpers.CompressRanges(input);

            CollectionAssert.AreEqual(output, actual);
        }

        [TestCase]
        public void TestRangeCount1()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(81), new PortOrRange(82, 83), new PortOrRange(85), new PortOrRange(86, 90) };

            Assert.AreEqual(1, PortRangeHelpers.CountRequiredMultiports(input));
        }

        [TestCase]
        public void TestRangeCount2()
        {
            List<PortOrRange> input = new List<PortOrRange> { new PortOrRange(80), new PortOrRange(81), new PortOrRange(82, 83), new PortOrRange(85), new PortOrRange(86, 90), new PortOrRange(180) };

            Assert.AreEqual(1, PortRangeHelpers.CountRequiredMultiports(input));
        }

        [TestCase]
        public void TestRangeCount3()
        {
            List<PortOrRange> input = new List<PortOrRange> { };

            for (int i = 0; i < 15; i++)
            {
                input.Add(new PortOrRange((uint)(100 + i)));
            }

            Assert.AreEqual(1, PortRangeHelpers.CountRequiredMultiports(input));
        }

        [TestCase]
        public void TestRangeCount4()
        {
            List<PortOrRange> input = new List<PortOrRange> { };

            for (int i = 0; i < 16; i++)
            {
                input.Add(new PortOrRange((uint)(100 + i)));
            }

            Assert.AreEqual(2, PortRangeHelpers.CountRequiredMultiports(input));
        }

        [TestCase]
        public void TestRangeCount5()
        {
            List<PortOrRange> input = new List<PortOrRange> { };

            for (int i = 0; i < 8; i++)
            {
                input.Add(new PortOrRange((uint)(100*i),(uint)((100*i) + 1)));
            }

            Assert.AreEqual(2, PortRangeHelpers.CountRequiredMultiports(input));
        }

        [TestCase]
        public void TestRangeCount6()
        {
            List<PortOrRange> input = new List<PortOrRange> { };

            for (int i = 0; i < 15; i++)
            {
                input.Add(new PortOrRange((uint)(100 + i)));
            }

            Assert.AreEqual(1, PortRangeHelpers.CountRequiredMultiports(input));
        }
    }
}
