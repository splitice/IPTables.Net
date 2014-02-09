using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.Modules.Comment
{
    public static class CommentRuleExtension
    {
        public static void SetComment(this IpTablesRule rule, String commentText)
        {
            var commentModule = rule.GetModuleOrLoad<CommentModule>("comment");
            commentModule.CommentText = commentText;
        }
    }
}
