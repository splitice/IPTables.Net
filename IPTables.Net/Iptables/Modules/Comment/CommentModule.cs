using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.Modules.Comment
{
    public class CommentModule : ModuleBase, IEquatable<CommentModule>, IIpTablesModule
    {
        private const String OptionCommentLong = "--comment";

        public String CommentText;

        public CommentModule(int version) : base(version)
        {
        }

        public bool Equals(CommentModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(CommentText, other.CommentText);
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionCommentLong:
                    CommentText = parser.GetNextArg();
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (CommentText != null)
            {
                sb.Append("--comment ");
                sb.Append(ShellHelper.EscapeArguments(CommentText));
            }

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionCommentLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("comment", typeof (CommentModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((CommentModule) obj);
        }

        public override int GetHashCode()
        {
            return (CommentText != null ? CommentText.GetHashCode() : 0);
        }
    }
}