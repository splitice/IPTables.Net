using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace IPTables.Net.Iptables
{
    public class IpTablesRuleBuilder
    {
        public IpTablesRuleBuilder() :
            this(compactMode: false, strictMode: false)
        {
        }

        /// <summary>
        /// Construct rule builder with full control of behaviour 
        /// </summary>
        /// <param name="compactMode">
        /// Determine type of name of parameter in rule result
        /// <example>
        /// if compactMode set to true, result of AddJump is --jump value
        /// but if compactMode set to false, result of AddJump is -j value
        /// </example>
        /// </param>
        /// <param name="strictMode">
        /// Determine empty value cause to error or not, and in general determine strict input validation or not
        /// </param>
        public IpTablesRuleBuilder(bool compactMode, bool strictMode)
        {
            stringBuilder = new StringBuilder();
            this.compactMode = compactMode;
            this.strictMode = strictMode;
            this.trasnportModuleUsed = false;
            this.protocol = string.Empty;
        }

        /// <summary>
        /// This specifies the target of the rule; i.e., what to do if the packet matches it.
        /// The target can be a user-defined chain (other than the one this rule is in),
        /// one of the special builtin targets which decide the fate of the packet immediately,
        /// or an extension (see EXTENSIONS below). If this option is omitted in a rule (and -g is not used),
        /// then matching the rule will have no effect on the packet's fate, but the counters on the rule will be incremented.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="caller"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public IpTablesRuleBuilder AddJump(string value, [CallerMemberName] string caller = null)
        {
            if (string.IsNullOrEmpty(value))
            {
                if (strictMode)
                    throw new ArgumentNullException(caller);
                return this;
            }

            string parameter = compactMode ? "-j" : "--jump";
            stringBuilder.Append($" {parameter} {value}");

            return this;
        }

        /// <summary>
        /// Name of an interface via which a packet was received (only for packets entering the INPUT, FORWARD and PREROUTING chains).
        /// When the "!" argument is used before the interface name, the sense is inverted.
        /// If the interface name ends in a "+", then any interface which begins with this name will match.
        /// If this option is omitted, any interface name will match.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public IpTablesRuleBuilder AddInboundInterface(string value, [CallerMemberName] string caller = null)
        {
            if (string.IsNullOrEmpty(value))
            {
                if (strictMode)
                    throw new ArgumentNullException(caller);
                return this;
            }

            string parameter = compactMode ? "-i" : "--in-interface";
            stringBuilder.Append($" {parameter} {value}");

            return this;
        }

        /// <summary>
        /// Name of an interface via which a packet is going to be sent (for packets entering the FORWARD, OUTPUT and POSTROUTING chains).
        /// When the "!" argument is used before the interface name, the sense is inverted.
        /// If the interface name ends in a "+", then any interface which begins with this name will match.
        /// If this option is omitted, any interface name will match.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public IpTablesRuleBuilder AddOutboundInterface(string value, [CallerMemberName] string caller = null)
        {
            if (string.IsNullOrEmpty(value))
            {
                if (strictMode)
                    throw new ArgumentNullException(caller);
                return this;
            }

            string parameter = compactMode ? "-o" : "--out-interface";
            stringBuilder.Append($" {parameter} {value}");

            return this;
        }

        /// <summary>
        /// The protocol of the rule or of the packet to check.
        /// The specified protocol can be one of tcp, udp, icmp, or all, or it can be a numeric value,
        /// representing one of these protocols or a different one. A protocol name from /etc/protocols is also allowed.
        /// A "!" argument before the protocol inverts the test. The number zero is equivalent to all.
        /// Protocol all will match with all protocols and is taken as default when this option is omitted.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="caller"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public IpTablesRuleBuilder AddProtocol(string value, [CallerMemberName] string caller = null)
        {
            if (string.IsNullOrEmpty(value))
            {
                if (strictMode)
                    throw new ArgumentNullException(caller);
                return this;
            }

            // TODO: in some case -p means port, so we have to investigate more
            string parameter = compactMode ? "-p" : "--protocol";
            stringBuilder.Append($" {parameter} {value}");
            protocol = value;

            return this;
        }

        /// <summary>
        /// Source specification. Address can be either a network name,
        /// a hostname (please note that specifying any name to be resolved with a remote query such as DNS is a really bad idea),
        /// a network IP address (with /mask), or a plain IP address.
        /// The mask can be either a network mask or a plain number, specifying the number of 1's at the left side of the network mask.
        /// Thus, a mask of 24 is equivalent to 255.255.255.0. A "!" argument before the address specification inverts the sense of the address.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public IpTablesRuleBuilder AddSourceIp(string value, [CallerMemberName] string caller = null)
        {
            if (string.IsNullOrEmpty(value))
            {
                if (strictMode)
                    throw new ArgumentNullException(caller);
                return this;
            }

            string parameter = compactMode ? "-s" : "--source";
            stringBuilder.Append($" {parameter} {value}");

            return this;
        }

        /// <summary>
        /// Destination specification. <seealso cref="AddSourceIp"/>
        /// </summary>
        /// <param name="value"></param>
        /// <param name="caller">Internal usage</param>
        /// <returns></returns>
        public IpTablesRuleBuilder AddDestinationIp(string value, [CallerMemberName] string caller = null)
        {
            if (string.IsNullOrEmpty(value))
            {
                if (strictMode)
                    throw new ArgumentNullException(caller);
                return this;
            }

            string parameter = compactMode ? "-d" : "--destination";
            stringBuilder.Append($" {parameter} {value}");

            return this;
        }

        /// <summary>
        /// Source port or port range specification.
        /// This can either be a service name or a port number.
        /// An inclusive range can also be specified, using the format port:port.
        /// If the first port is omitted, "0" is assumed; if the last is omitted, "65535" is assumed.
        /// If the second port greater then the first they will be swapped.
        ///
        /// It can only be used in conjunction with -p tcp or -p udp.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="caller"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public IpTablesRuleBuilder AddSourcePort(string value, [CallerMemberName] string caller = null)
        {
            if (string.IsNullOrEmpty(value))
            {
                if (strictMode)
                    throw new ArgumentNullException(caller);
                return this;
            }

            string parameter = compactMode ? "--sport" : "--source-port";
            stringBuilder.Append($" {parameter} {value}");
            trasnportModuleUsed = true;

            return this;
        }

        /// <summary>
        /// Destination port or port range specification.
        /// 
        /// It can only be used in conjunction with -p tcp or -p udp.
        /// <seealso cref="AddSourcePort"/>
        /// </summary>
        /// <param name="value"></param>
        /// <param name="caller"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public IpTablesRuleBuilder AddDestinationPort(string value, [CallerMemberName] string caller = null)
        {
            if (string.IsNullOrEmpty(value))
            {
                if (strictMode)
                    throw new ArgumentNullException(caller);
                return this;
            }

            string parameter = compactMode ? "--dport" : "--destination-port";
            stringBuilder.Append($" {parameter} {value}");
            trasnportModuleUsed = true;


            return this;
        }

        /// <summary>
        /// Serialize all parameter in form of iptables rule 
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            if (trasnportModuleUsed)
            {
                stringBuilder.Insert(0, $"-m {protocol}");
            }

            return stringBuilder.ToString();
        }

        private readonly StringBuilder stringBuilder;
        private readonly bool compactMode;
        private readonly bool strictMode;
        private bool trasnportModuleUsed;
        private string protocol;
    }
}
