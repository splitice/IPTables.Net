using System;

namespace IPTables.Net.Iptables.DataTypes
{
    public class ConnectionStateHelper
    {
        public static String GetString(ConnectionState state)
        {
            switch (state)
            {
                case ConnectionState.Established:
                    return "ESTABLISHED";

                case ConnectionState.Invalid:
                    return "INVALID";

                case ConnectionState.New:
                    return "NEW";

                case ConnectionState.Related:
                    return "RELATED";

                case ConnectionState.Untracked:
                    return "UNTRACKED";
            }

            throw new Exception("Unknown connection state");
        }

        public static ConnectionState FromString(String state)
        {
            switch (state)
            {
                case "ESTABLISHED":
                    return ConnectionState.Established;
                case "INVALID":
                    return ConnectionState.Invalid;
                case "NEW":
                    return ConnectionState.New;
                case "RELATED":
                    return ConnectionState.Related;
                case "UNTRACKED":
                    return ConnectionState.Untracked;
            }

            throw new Exception("Unknown connection stat: " + state);
        }
    }
}