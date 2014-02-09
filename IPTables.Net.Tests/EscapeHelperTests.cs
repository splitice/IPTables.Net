using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Common;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class EscapeHelperTests
    {
        [Test]
        public void TestSpaces()
        {
            Assert.AreEqual("'a word'", Helpers.EscapeArguments("a word"));
            Assert.AreEqual("singleword", Helpers.EscapeArguments("singleword"));
        }

        [Test]
        public void TestPipe()
        {
            Assert.AreEqual("'|'", Helpers.EscapeArguments("|"));
            Assert.AreEqual("'a|word'", Helpers.EscapeArguments("a|word"));
            Assert.AreEqual("singleword", Helpers.EscapeArguments("singleword"));
        }
    }
}
