using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using SystemInteract;
using IPTables.Net.Exceptions;
using IPTables.Net.Supporting;
namespace IPTables.Net.NfAcct
{
    public class NfAcct
    {
        private readonly ISystemFactory _system;
        public NfAcct(ISystemFactory system) { _system = system; }
        private string Execute(params string[] arguments)
        {
            using var process = _system.StartProcess("/usr/sbin/nfacct", ShellHelper.BuildArgumentString(arguments));
            ProcessHelper.ReadToEnd(process, out var output, out var error);
            // nfacct reports a missing object as ENOENT with exit status 1.
            // Match only its get-response diagnostic, not socket or process-start failures.
            if (process.ExitCode == 1 && arguments[0] == "get" && string.IsNullOrWhiteSpace(output) &&
                Regex.IsMatch(error.Trim(), @"\Anfacct v[^:\r\n]+: error: No such file or directory\z"))
                return "";
            if (process.ExitCode != 0) throw new IpTablesNetException($"nfacct exited with {process.ExitCode}: {error} {output}");
            return output;
        }
        private static List<NfAcctUsage> Parse(string output)
        {
            if (string.IsNullOrWhiteSpace(output)) return new List<NfAcctUsage>();
            try
            {
                return XDocument.Parse(output).Descendants("obj").Select(node =>
                {
                    var name = (string)node.Element("name");
                    if (string.IsNullOrEmpty(name) || !ulong.TryParse((string)node.Element("bytes"), out var bytes) ||
                        !ulong.TryParse((string)node.Element("pkts"), out var packets))
                        throw new FormatException("Invalid nfacct object: name, bytes and pkts are required.");
                    return new NfAcctUsage(name, bytes, packets);
                }).ToList();
            }
            catch (XmlException ex) { throw new FormatException("Invalid nfacct XML", ex); }
        }
        /// <summary>Gets accounting data, or null if the object does not exist.</summary>
        public NfAcctUsage Get(string name, bool reset = false) =>
            Parse(Execute(reset ? new[] { "get", name, "xml", "reset" } : new[] { "get", name, "xml" })).FirstOrDefault(x => x.Name == name);
        public bool Exist(string name) => Get(name) != null;
        public void Add(string name) => Execute("add", name);
        public void Delete(string name) => Execute("del", name);
        public List<NfAcctUsage> List(bool reset = false) => Parse(Execute(reset ? new[] { "list", "xml", "reset" } : new[] { "list", "xml" }));
    }
}
