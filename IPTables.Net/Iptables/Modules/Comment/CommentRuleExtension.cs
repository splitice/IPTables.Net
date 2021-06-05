using System;

namespace IPTables.Net.Iptables.Modules.Comment
{
    public static class CommentRuleExtension
    {
        public static void SetComment(this IpTablesRule rule, string commentText)
        {
            var commentModule = rule.GetModuleOrLoad<CommentModule>("comment");
            commentModule.CommentText = commentText;
        }
    }
}