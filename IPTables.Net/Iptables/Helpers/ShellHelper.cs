namespace IPTables.Net.Iptables.Helpers
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

            if (original.IndexOfAny(new[] {'|', ' ', '\\', '"', '\''}) == -1)
                return original;

            return "'" + original.Replace("\\", "\\\\").Replace("'", "\\'") + "'";
        }
    }
}