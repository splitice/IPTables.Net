using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Supporting;

namespace IPTables.Net.Tests
{
    public class EscapeHelperTests
    {
        [Fact]
        public void TestSpaces()
        {
            Assert.Equal("'a word'", ShellHelper.EscapeArguments("a word"));
            Assert.Equal("singleword", ShellHelper.EscapeArguments("singleword"));
        }

        [Fact]
        public void TestPipe()
        {
            Assert.Equal("'|'", ShellHelper.EscapeArguments("|"));
            Assert.Equal("'a|word'", ShellHelper.EscapeArguments("a|word"));
            Assert.Equal("singleword", ShellHelper.EscapeArguments("singleword"));
        }
        [Fact]
        public void TestSpace()
        {
            Assert.Equal("a word", ShellHelper.BuildArgumentString(new []{"a", "word"}));
            Assert.Equal("\"two words\"", ShellHelper.BuildArgumentString(new[] { "two words" }));
            Assert.Equal("\"two words and \\\"punctuation\\\"\"", ShellHelper.BuildArgumentString(new[] { "two words and \"punctuation\"" }));
            Assert.Equal("bash -c \"bash -c \\\"echo a\\\"\"", ShellHelper.BuildArgumentString(new[] { "bash", "-c", ShellHelper.BuildArgumentString(new []{"bash", "-c", "echo a"}) }));
            Assert.Equal("bash -c \"bash -c \\\"echo \\\\\\\"a\\\\\\\"\\\"\"", ShellHelper.BuildArgumentString(new[] { "bash", "-c", ShellHelper.BuildArgumentString(new[] { "bash", "-c", "echo \"a\"" }) }));
        }
    }
}
