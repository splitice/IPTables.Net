using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables
{
    /// <summary>
    /// Data to define the default IPTables tables and chains
    /// </summary>
    public static class IPTablesTables
    {
        /// <summary>
        /// The filter table is one of the most widely used tables in iptables.
        /// The filter table is used to make decisions about whether to let a packet continue to its intended destination or to deny its request.
        /// In firewall parlance, this is known as “filtering” packets.
        /// This table provides the bulk of functionality that people think of when discussing firewalls.
        /// </summary>
        public const string Filter = "filter";

        /// <summary>
        /// The nat table is used to implement network address translation rules.
        /// As packets enter the network stack, rules in this table will determine whether
        /// and how to modify the packet’s source or destination addresses in order to impact
        /// the way that the packet and any response traffic are routed.
        ///
        /// This is often used to route packets to networks when direct access is not possible.
        /// </summary>
        public const string Nat = "nat";

        /// <summary>
        /// The mangle table is used to alter the IP headers of the packet in various ways.
        /// For instance, you can adjust the TTL (Time to Live) value of a packet,
        /// either lengthening or shortening the number of valid network hops the packet can sustain.
        /// Other IP headers can be altered in similar ways.
        ///
        /// This table can also place an internal kernel “mark” on the packet for further processing in other tables and by other networking tools.
        /// This mark does not touch the actual packet, but adds the mark to the kernel’s representation of the packet.
        /// </summary>
        public const string Mangle = "mangle";

        /// <summary>
        /// The iptables firewall is stateful, meaning that packets are evaluated in regards to their relation to previous packets.
        /// The connection tracking features built on top of the netfilter framework allow iptables to view packets
        /// as part of an ongoing connection or session instead of as a stream of discrete, unrelated packets.
        /// The connection tracking logic is usually applied very soon after the packet hits the network interface.
        ///
        /// The raw table has a very narrowly defined function.
        /// Its only purpose is to provide a mechanism for marking packets in order to opt-out of connection tracking.
        /// </summary>
        public const string Raw = "raw";

        /// <summary>
        /// The security table is used to set internal SELinux security context marks on packets,
        /// which will affect how SELinux or other systems that can interpret SELinux security contexts handle the packets.
        /// These marks can be applied on a per-packet or per-connection basis.
        /// </summary>
        public const string Security = "security";

        public static Dictionary<string, List<string>> DefaultTables = new Dictionary<string, List<string>>
        {
            {Filter, new List<string> {IpTablesChain.Input, IpTablesChain.Forward, IpTablesChain.Output}},
            {Nat, new List<string> {IpTablesChain.Prerouting, IpTablesChain.Postrouting, IpTablesChain.Input, IpTablesChain.Output}},
            {Raw, new List<string> {IpTablesChain.Prerouting, IpTablesChain.Output}},
            {Mangle, new List<string> {IpTablesChain.Input, IpTablesChain.Forward, IpTablesChain.Output, IpTablesChain.Prerouting, IpTablesChain.Postrouting}},
            {Security, new List<string> {IpTablesChain.Input, IpTablesChain.Forward, IpTablesChain.Output}},
        };

        internal static List<string> GetInternalChains(string table)
        {
            List<string> ret;
            if (!DefaultTables.TryGetValue(table, out ret))
                throw new IpTablesNetException(string.Format("Unknown Table: {0}", table));

            return ret;
        }

        internal static bool IsInternalChain(string table, string chain)
        {
            return GetInternalChains(table).Contains(chain);
        }
    }
}