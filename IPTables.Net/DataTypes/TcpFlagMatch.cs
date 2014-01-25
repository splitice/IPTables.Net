using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


namespace IPTables.Net.DataTypes
{
    class TcpFlagMatch
    {
        public HashSet<TcpFlag> Comparing = new HashSet<TcpFlag>();
        public HashSet<TcpFlag> MustHave = new HashSet<TcpFlag>();

        private TcpFlagMatch(IEnumerable<TcpFlag> tcpComparing, IEnumerable<TcpFlag> tcpMustHave)
        {
            Comparing.UnionWith(tcpComparing);
            MustHave.UnionWith(tcpMustHave);
        }

        public HashSet<TcpFlag> MustNotHave
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public static TcpFlagMatch Syn = new TcpFlagMatch(
            new List<TcpFlag>() { TcpFlag.SYN, TcpFlag.RST, TcpFlag.ACK, TcpFlag.FIN }, new List<TcpFlag>() { TcpFlag.SYN });

        public static TcpFlagMatch NotSyn = new TcpFlagMatch(
            new List<TcpFlag>() { TcpFlag.SYN }, new List<TcpFlag>() { });

        public String ToString()
        {
            return "";
        }

        static TcpFlag GetFlag(String sFlag)
        {
            switch (sFlag)
            {
                case "SYN":
                    return TcpFlag.SYN;
                case "ACK":
                    return TcpFlag.ACK;
                case "FIN":
                    return TcpFlag.FIN;
                case "RST":
                    return TcpFlag.RST;
            }

            throw new Exception("Invalid TCP Flag");
        }

        static IEnumerable<TcpFlag> GetFlags(String sFlags)
        {
            List<TcpFlag> flags = new List<TcpFlag>();
            foreach (var f in sFlags.Split(new char[] {','}))
            {
                flags.Add(GetFlag(f));
            }
            return flags;
        }

        public static TcpFlagMatch Parse(string getNextArg)
        {
            var split = getNextArg.Split(new char[] {' '});

            return new TcpFlagMatch(GetFlags(split[0]), GetFlags(split[1]));
        }
    }
}
