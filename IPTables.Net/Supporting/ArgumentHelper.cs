using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Supporting
{
    public class ArgumentHelper
    {
        public static string[] SplitArguments(string commandLine)
        {
            char[] parmChars = commandLine.ToCharArray();
            bool inSingleQuote = false;
            bool inDoubleQuote = false;
            for (int index = 0; index < parmChars.Length; index++)
            {
                if (parmChars[index] == '"' && !inSingleQuote)
                {
                    inDoubleQuote = !inDoubleQuote;
                    parmChars[index] = '\x00';
                }
                if (parmChars[index] == '\'' && !inDoubleQuote)
                {
                    inSingleQuote = !inSingleQuote;
                    parmChars[index] = '\x00';
                }
                if (!inSingleQuote && !inDoubleQuote && parmChars[index] == ' ')
                    parmChars[index] = '\x01';
            }
            return (new string(parmChars)).Replace("\x00", "").Split(new[] { '\x01' }, StringSplitOptions.RemoveEmptyEntries);
        }
    }
}
