using System;
using IPTables.Net.Supporting;
namespace IPTables.Net.Tests;
public class ArgumentHelperTests
{
    [Theory]
    [InlineData("a\tb  c", "a", "b", "c")]
    [InlineData("'' \"\" x", "", "", "x")]
    [InlineData("'two words' \"O'Brien\" path\\name", "two words", "O'Brien", "path\\name")]
    [InlineData("'it\\'s' \"say \\\"hi\\\"\" a\\ b", "it's", "say \"hi\"", "a b")]
    public void TokenizationHasIndependentExpectedValues(string input, string a, string b, string c)
    { Assert.Equal(new[] { a, b, c }, ArgumentHelper.SplitArguments(input)); }
    [Fact]
    public void EmptyAndUnterminatedInput()
    {
        Assert.Empty(ArgumentHelper.SplitArguments("")); Assert.Empty(ArgumentHelper.SplitArguments(" \t\r\n"));
        Assert.Throws<FormatException>(() => ArgumentHelper.SplitArguments("'open"));
    }
}
