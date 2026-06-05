using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers.Subnet.Graph;
using IPTables.Net.Iptables.Modules;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Tests.MockSystem;

namespace IPTables.Net.Tests
{
    public class GraphLayoutTests
    {
        [Fact]
        public void TestAddSingles()
        {
            List<IpCidr> addresses = new List<IpCidr>();
            for (int i = 0; i < 250; i++)
            {
                addresses.Add(new IpCidr(IPAddress.Parse("1.1.1."+i),32));
            }

            CidrGraph graph = CidrGraph.BuildGraph(addresses);

            //These numbers are based on the best I could do on paper. This less than perfect algorithm can beat that.
            Assert.True(graph.CalculateMaxPathLength() < 20, "Criteria for a good algorithm (max): " + graph.CalculateMaxPathLength());
            Assert.True(graph.CalculateMinPathLength() < 10, "Criteria for a good algorithm (min): " + graph.CalculateMinPathLength());
            Assert.True(graph.CalculateAveragePathLength() < 11, "Criteria for a good algorithm (avg): " + graph.CalculateAveragePathLength());
        }

        
    }
}
