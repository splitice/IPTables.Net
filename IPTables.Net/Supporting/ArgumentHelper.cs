using System;
using System.Collections.Generic;
using System.Text;
namespace IPTables.Net.Supporting
{
    public class ArgumentHelper
    {
        public static string[] SplitArguments(string commandLine)
        {
            ArgumentNullException.ThrowIfNull(commandLine);
            var result = new List<string>(); var token = new StringBuilder();
            char quote = '\0'; bool started = false;
            for (int i = 0; i < commandLine.Length; i++)
            {
                char c = commandLine[i];
                if (c == '\\' && i + 1 < commandLine.Length &&
                    (commandLine[i + 1] == '\\' || commandLine[i + 1] == quote ||
                     (quote == '\0' && (char.IsWhiteSpace(commandLine[i + 1]) || commandLine[i + 1] == '\'' || commandLine[i + 1] == '"'))))
                { token.Append(commandLine[++i]); started = true; }
                else if (quote != '\0')
                { if (c == quote) quote = '\0'; else token.Append(c); started = true; }
                else if (c == '\'' || c == '"') { quote = c; started = true; }
                else if (char.IsWhiteSpace(c))
                {
                    if (started) { result.Add(token.ToString()); token.Clear(); started = false; }
                }
                else { token.Append(c); started = true; }
            }
            if (quote != '\0') throw new FormatException("Unterminated quoted argument");
            if (started) result.Add(token.ToString());
            return result.ToArray();
        }
    }
}
