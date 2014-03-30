using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Helpers;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class EscapeHelperTests
    {
        [Test]
        public void TestSpaces()
        {
            Assert.AreEqual("'a word'", ShellHelper.EscapeArguments("a word"));
            Assert.AreEqual("singleword", ShellHelper.EscapeArguments("singleword"));
        }

        [Test]
        public void TestPipe()
        {
            Assert.AreEqual("'|'", ShellHelper.EscapeArguments("|"));
            Assert.AreEqual("'a|word'", ShellHelper.EscapeArguments("a|word"));
            Assert.AreEqual("singleword", ShellHelper.EscapeArguments("singleword"));
        }
    }
}
