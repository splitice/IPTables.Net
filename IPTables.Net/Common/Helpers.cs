using System;
using System.Text;
using System.Text.RegularExpressions;

namespace IPTables.Net.Common
{
    internal class Helpers
    {
        /// <summary>
        /// Encodes an argument for passing into a program
        /// </summary>
        /// <param name="original">The value that should be received by the program</param>
        /// <returns>The value which needs to be passed to the program for the original value 
        /// to come through</returns>
        public static string EscapeArguments(string original)
        {
            if (string.IsNullOrEmpty(original))
                return original;

            if (original.IndexOfAny(new char[] {'|', ' ', '\\', '"', '\''}) == -1)
                return original;

            return "'" + original.Replace("\\", "\\\\").Replace("'", "\\'") + "'";
        }
    }
}