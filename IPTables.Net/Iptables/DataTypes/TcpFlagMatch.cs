using System;
using System.Collections.Generic;
using System.Linq;

namespace IPTables.Net.Iptables.DataTypes
{
    internal class TcpFlagMatch
    {
        public static TcpFlagMatch Syn = new TcpFlagMatch(
            new List<TcpFlag> {TcpFlag.SYN, TcpFlag.RST, TcpFlag.ACK, TcpFlag.FIN}, new List<TcpFlag> {TcpFlag.SYN});

        public static TcpFlagMatch NotSyn = new TcpFlagMatch(
            new List<TcpFlag> {TcpFlag.SYN}, new List<TcpFlag>());

        public HashSet<TcpFlag> Comparing = new HashSet<TcpFlag>();
        public HashSet<TcpFlag> MustHave = new HashSet<TcpFlag>();

        private TcpFlagMatch(IEnumerable<TcpFlag> tcpComparing, IEnumerable<TcpFlag> tcpMustHave)
        {
            Comparing.UnionWith(tcpComparing);
            MustHave.UnionWith(tcpMustHave);
        }

        public HashSet<TcpFlag> MustNotHave
        {
            get { throw new NotImplementedException(); }
        }

        public override String ToString()
        {
            String ret = "";
            ret += Comparing.Select(f => GetFlag(f)).Aggregate((current, next) => current + ", " + next);
            ret += MustHave.Select(f => GetFlag(f)).Aggregate((current, next) => current + ", " + next);
            return ret;
        }

        private static TcpFlag GetFlag(String sFlag)
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

        private static String GetFlag(TcpFlag sFlag)
        {
            switch (sFlag)
            {
                case TcpFlag.SYN:
                    return "SYN";
                case TcpFlag.ACK:
                    return "ACK";
                case TcpFlag.FIN:
                    return "FIN";
                case TcpFlag.RST:
                    return "RST";
            }

            throw new Exception("Invalid TCP Flag");
        }

        private static IEnumerable<TcpFlag> GetFlags(String sFlags)
        {
            var flags = new List<TcpFlag>();
            foreach (string f in sFlags.Split(new[] {','}))
            {
                flags.Add(GetFlag(f));
            }
            return flags;
        }

        public static TcpFlagMatch Parse(string getNextArg)
        {
            string[] split = getNextArg.Split(new[] {' '});

            return new TcpFlagMatch(GetFlags(split[0]), GetFlags(split[1]));
        }
    }
}