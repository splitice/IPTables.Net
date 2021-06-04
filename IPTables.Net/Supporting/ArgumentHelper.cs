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
            bool inSpace = true;
            int lastChar = 0;
            for (int index = 0; index < parmChars.Length; index++)
            {
                // replace double quote with 0x00 if not in single quote
                if (parmChars[index] == '"' && !inSingleQuote)
                {
                    inDoubleQuote = !inDoubleQuote;
                    parmChars[index] = '\x00';
                }

                // replace single quote with 0x00 if not in single quote
                if (parmChars[index] == '\'' && !inDoubleQuote)
                {
                    inSingleQuote = !inSingleQuote;
                    parmChars[index] = '\x00';
                }

                // replace space with 0x01 if not in any quotes
                if (parmChars[index] == ' ' && !inSingleQuote && !inDoubleQuote)
                {
                    if (inSpace)
                    {
                        parmChars[index] = '\x00';
                    }
                    else
                    {
                        parmChars[index] = '\x01';
                        inSpace = true;
                    }
                }
                else
                {
                    lastChar = index;
                    inSpace = false;
                }
            }
            
            // remove all ignore chars (0x00), then split by space seperator (0x01)
            return (new string(parmChars, 0, lastChar + 1)).Replace("\x00", "").Split(new[] { '\x01' });
        }
    }
}
