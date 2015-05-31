using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using SystemInteract;

namespace IPTables.Net.Netfilter.Utils
{
    public class NfAcct
    {
        private NfAcctUsage FromXml(String output, String name)
        {
            XDocument doc;
            try
            {
                doc = XDocument.Parse(output);
            }
            catch (XmlException)
            {
                return null;
            }
            var usages = from node in doc.Descendants("obj")
                         where node.Descendants("name").First().Value == name
                         select new NfAcctUsage(node.Descendants("name").First().Value, ulong.Parse(node.Descendants("pkts").First().Value), ulong.Parse(node.Descendants("bytes").First().Value));

            return usages.FirstOrDefault();
        }

        public NfAcctUsage Get(String name, ISystemFactory system, bool reset = false)
        {
            String cmd = "get {0} xml";
            if (reset)
            {
                cmd += " reset";
            }

            var process = system.StartProcess("/usr/sbin/nfacct", String.Format(cmd, name));
            process.WaitForExit();
            var output = process.StandardOutput.ReadToEnd();
            if (output.Trim().Length == 0)
            {
                return null;
            }
            return FromXml(output, name);
        }

        public bool Exist(String name, ISystemFactory system)
        {
            return Get(name, system) != null;
        }

        public void Add(String name, ISystemFactory system)
        {
            String cmd = "add {0}";
            var process = system.StartProcess("/usr/sbin/nfacct", String.Format(cmd, name));
            process.WaitForExit();
            var output = process.StandardOutput.ReadToEnd();
        }

        public void Delete(String name, ISystemFactory system)
        {
            String cmd = "del {0}";
            var process = system.StartProcess("/usr/sbin/nfacct", String.Format(cmd, name));
            process.WaitForExit();
            var output = process.StandardOutput.ReadToEnd();
        }

        public List<NfAcctUsage> List(ISystemFactory system)
        {
            String cmd = "list xml";
            var process = system.StartProcess("/usr/sbin/nfacct", cmd);
            process.WaitForExit();
            var output = process.StandardOutput.ReadToEnd();

            var doc = XDocument.Parse(output);
            var usages = from node in doc.Descendants("obj")
                         select new NfAcctUsage(node.Descendants("name").First().Value, ulong.Parse(node.Descendants("pkts").First().Value), ulong.Parse(node.Descendants("bytes").First().Value));

            return usages.ToList();
        }
    }
}
