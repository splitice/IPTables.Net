using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using IPTables.Net.DataTypes;
using IPTables.Net.Modules.Base;

namespace IPTables.Net.Modules
{
    class Comment : ModuleBase, IIptablesModule
    {
        private const String OptionCommentLong = "--comment";

        public String CommentText;

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionCommentLong:
                    CommentText = parser.GetNextArg();
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            StringBuilder sb = new StringBuilder();

            if (CommentText != null)
            {
                sb.Append("--comment ");
                sb.Append(Helpers.EscapeArguments(CommentText));
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
                          {
                              OptionCommentLong
                          };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("comment", typeof (Comment), GetOptions);
        }
    }
}
