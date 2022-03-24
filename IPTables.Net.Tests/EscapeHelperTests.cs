using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Supporting;
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
        [Test]
        public void TestSpace()
        {
            Assert.AreEqual("a word", ShellHelper.BuildArgumentString(new []{"a", "word"}));
            Assert.AreEqual("\"two words\"", ShellHelper.BuildArgumentString(new[] { "two words" }));
            Assert.AreEqual("\"two words and \\\"punctuation\\\"\"", ShellHelper.BuildArgumentString(new[] { "two words and \"punctuation\"" }));
            Assert.AreEqual("bash -c \"bash -c \\\"echo a\\\"\"", ShellHelper.BuildArgumentString(new[] { "bash", "-c", ShellHelper.BuildArgumentString(new []{"bash", "-c", "echo a"}) }));
            Assert.AreEqual("bash -c \"bash -c \\\"echo \\\\\\\"a\\\\\\\"\\\"\"", ShellHelper.BuildArgumentString(new[] { "bash", "-c", ShellHelper.BuildArgumentString(new[] { "bash", "-c", "echo \"a\"" }) }));
        }
    }
}
