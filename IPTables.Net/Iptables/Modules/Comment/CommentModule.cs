using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Common;
using IPTables.Net.Iptables.Modules.Base;

namespace IPTables.Net.Iptables.Modules.Comment
{
    public class CommentModule : ModuleBase, IIptablesModule, IEquatable<CommentModule>
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
            var sb = new StringBuilder();

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
            return GetModuleEntryInternal("comment", typeof (CommentModule), GetOptions);
        }

        public bool Equals(CommentModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(CommentText, other.CommentText);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((CommentModule) obj);
        }

        public override int GetHashCode()
        {
            return (CommentText != null ? CommentText.GetHashCode() : 0);
        }
    }
}