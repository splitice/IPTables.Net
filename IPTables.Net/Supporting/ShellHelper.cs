using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace IPTables.Net.Supporting
{
    public class ShellHelper
    {
        /// <summary>
        ///     Encodes an argument for passing into a program
        /// </summary>
        /// <param name="original">The value that should be received by the program</param>
        /// <returns>
        ///     The value which needs to be passed to the program for the original value
        ///     to come through
        /// </returns>
        public static string EscapeArguments(string original)
        {
            if (string.IsNullOrEmpty(original))
                return original;

            if (original.IndexOfAny(new[] { '|', ' ', '\\', '"', '\'', '>', '&' }) == -1)
                return original;

            return "'" + original.Replace("\\", "\\\\").Replace("'", "\\'") + "'";
        }

        /// <summary>
        /// Undo the processing which took place to create string[] args in Main, so that the next process will
        /// receive the same string[] args.
        /// </summary>
        /// <param name="args">The arguments</param>
        /// <returns>A single string of escaped arguments</returns>
        public static string BuildArgumentString(string[] args)
        {
            StringBuilder arguments = new StringBuilder();
            Regex invalidChar = new Regex("[\x00\x0a\x0d]");//  these can not be escaped
            Regex needsQuotes = new Regex(@"\s|""");//          contains whitespace or two quote characters
            Regex escapeQuote = new Regex(@"(\\*)(""|$)");//    one or more '\' followed with a quote or end of string
            for (int carg = 0; args != null && carg < args.Length; carg++)
            {
                if (args[carg] == null) { throw new ArgumentNullException("args[" + carg + "]"); }
                if (invalidChar.IsMatch(args[carg])) { throw new ArgumentOutOfRangeException("args[" + carg + "]"); }
                if (args[carg] == String.Empty) { arguments.Append("\"\""); }
                else if (!needsQuotes.IsMatch(args[carg])) { arguments.Append(args[carg]); }
                else
                {
                    arguments.Append('"');
                    arguments.Append(escapeQuote.Replace(args[carg], m =>
                        m.Groups[1].Value + m.Groups[1].Value +
                        (m.Groups[2].Value == "\"" ? "\\\"" : "")
                    ));
                    arguments.Append('"');
                }
                if (carg + 1 < args.Length)
                    arguments.Append(' ');
            }
            return arguments.ToString();
        }

        /// <summary>
        /// Undo the processing which took place to create string[] args in Main, so that the next process will
        /// receive the same string[] args.
        /// </summary>
        /// <param name="args">The arguments</param>
        /// <returns>A single string of escaped arguments</returns>
        public static string BuildArgumentString(List<string> args)
        {
            StringBuilder arguments = new StringBuilder();
            Regex invalidChar = new Regex("[\x00\x0a\x0d]");//  these can not be escaped
            Regex needsQuotes = new Regex(@"\s|""");//          contains whitespace or two quote characters
            Regex escapeQuote = new Regex(@"(\\*)(""|$)");//    one or more '\' followed with a quote or end of string
            for (int carg = 0; args != null && carg < args.Count; carg++)
            {
                if (args[carg] == null) { throw new ArgumentNullException("args[" + carg + "]"); }
                if (invalidChar.IsMatch(args[carg])) { throw new ArgumentOutOfRangeException("args[" + carg + "]"); }
                if (args[carg] == String.Empty) { arguments.Append("\"\""); }
                else if (!needsQuotes.IsMatch(args[carg])) { arguments.Append(args[carg]); }
                else
                {
                    arguments.Append('"');
                    arguments.Append(escapeQuote.Replace(args[carg], m =>
                        m.Groups[1].Value + m.Groups[1].Value +
                        (m.Groups[2].Value == "\"" ? "\\\"" : "")
                    ));
                    arguments.Append('"');
                }
                if (carg + 1 < args.Count)
                    arguments.Append(' ');
            }
            return arguments.ToString();
        }
    }
}