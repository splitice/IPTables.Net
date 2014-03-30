using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Helpers.Subnet.Graph
{
    class CidrGraphNode
    {
        public IpCidr Cidr;
        public List<CidrGraphNode> Children = new List<CidrGraphNode>();
        public CidrGraphNode Parent;

        public CidrGraphNode(CidrGraphNode parent)
        {
            Parent = parent;
        }

        public List<CidrGraphNode> GetEnds()
        {
            var l = new List<CidrGraphNode>();
            if (Children.Count == 0)
            {
                l.Add(this);
                return l;
            }

            foreach (var child in Children)
            {
                l.AddRange(child.GetEnds());
            }

            return l;
        }

        public int CalculateBFSLength()
        {
            int ret = 0;
            var t = this;
            while (t.Parent != null)
            {
                ret ++;
                ret += t.Parent.Children.IndexOf(t);
                t = t.Parent;
            }
            return ret;
        }

        public int CalculateNewChildBFSLength()
        {
            return 10+CalculateBFSLength() + Children.Count;
        }

        public IEnumerable<CidrGraphNode> GetNodes()
        {
            var l = new List<CidrGraphNode>();
            if (Children.Count == 0)
            {
                l.Add(this);
                return l;
            }

            l.Add(this);
            foreach (var child in Children)
            {
                l.AddRange(child.GetNodes());
            }

            return l;
        }
    }
}
