using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables.DataTypes
{
    public class TcpFlagMatch : IEquatable<TcpFlagMatch>
    {
        public static TcpFlagMatch Syn = new TcpFlagMatch(
            new List<TcpFlag> {TcpFlag.SYN, TcpFlag.RST, TcpFlag.ACK, TcpFlag.FIN}, new List<TcpFlag> {TcpFlag.SYN});

        public HashSet<TcpFlag> Comparing = new HashSet<TcpFlag>();
        public HashSet<TcpFlag> MustHave = new HashSet<TcpFlag>();

        private TcpFlagMatch(IEnumerable<TcpFlag> tcpComparing, IEnumerable<TcpFlag> tcpMustHave)
        {
            Comparing.UnionWith(tcpComparing);
            MustHave.UnionWith(tcpMustHave);
        }

        public bool Equals(TcpFlagMatch other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Comparing.SetEquals(other.Comparing) && MustHave.SetEquals(other.MustHave);
        }

        public override String ToString()
        {
            String ret = "";
            ret += Comparing.Select(GetFlag).Aggregate((current, next) => current + "," + next);
            ret += " " + MustHave.Select(GetFlag).Aggregate((current, next) => current + "," + next);
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
                case "URG":
                    return TcpFlag.URG;
                case "PSH":
                    return TcpFlag.PSH;
            }

            throw new IpTablesNetException("Invalid TCP Flag");
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
                case TcpFlag.URG:
                    return "URG";
                case TcpFlag.PSH:
                    return "PSH";
            }

            throw new IpTablesNetException("Invalid TCP Flag");
        }

        private static IEnumerable<TcpFlag> GetFlags(String sFlags)
        {
            if (sFlags == "ALL")
            {
                return new List<TcpFlag> {TcpFlag.ACK, TcpFlag.FIN, TcpFlag.PSH, TcpFlag.RST, TcpFlag.SYN, TcpFlag.URG};
            }
            if (sFlags == "NONE")
            {
                return new List<TcpFlag>();
            }
            var flags = new List<TcpFlag>();
            foreach (string f in sFlags.Split(new[] {','}))
            {
                flags.Add(GetFlag(f));
            }
            return flags;
        }

        public static TcpFlagMatch Parse(string comparing, string mustHave)
        {
            return new TcpFlagMatch(GetFlags(comparing), GetFlags(mustHave));
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((TcpFlagMatch) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((Comparing != null ? Comparing.GetHashCode() : 0)*397) ^
                       (MustHave != null ? MustHave.GetHashCode() : 0);
            }
        }
    }
}