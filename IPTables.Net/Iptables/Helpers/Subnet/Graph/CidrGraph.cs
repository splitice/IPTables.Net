using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Policy;
using System.Text;
using IPTables.Net.Iptables.DataTypes;
using LukeSkywalker.IPNetwork;

namespace IPTables.Net.Iptables.Helpers.Subnet.Graph
{
    public class PriorityQueue<T> : IEnumerable
    {
        List<T> items;
        List<int> priorities;

        public PriorityQueue()
        {
            items = new List<T>();
            priorities = new List<int>();
        }

        public IEnumerator GetEnumerator() { return items.GetEnumerator(); }
        public int Count { get { return items.Count; } }

        /// <returns>Index of new element</returns>
        public int Enqueue(T item, int priority)
        {
            for (int i = 0; i < priorities.Count; i++) //go through all elements...
            {
                if (priorities[i] > priority) //...as long as they have a lower priority.    low priority = low index
                {
                    items.Insert(i, item);
                    priorities.Insert(i, priority);
                    return i;
                }
            }

            items.Add(item);
            priorities.Add(priority);
            return items.Count - 1;
        }

        public T Dequeue()
        {
            T item = items[0];
            priorities.RemoveAt(0);
            items.RemoveAt(0);
            return item;
        }

        public T Peek()
        {
            return items[0];
        }

        public int PeekPriority()
        {
            return priorities[0];
        }
    }
    class CidrGraph
    {
        public CidrGraphNode Root;

        public double CalculateAveragePathLength()
        {
            return CalculateAveragePathLength(Root);
        }

        private static double CalculateAveragePathLength(CidrGraphNode node, int i = 1)
        {
            double ret = 0;
            int count = 0;
            foreach (var end in node.GetEnds())
            {
                ret += end.CalculateBFSLength();
                count++;
            }
            return ret/count;
        }


        public static int CalculateMaxPathLength(CidrGraphNode node)
        {
            int ret = 0;
            foreach (var end in node.GetEnds())
            {
                int bfslen = end.CalculateBFSLength();
                if (bfslen > ret)
                    ret = bfslen;
            }
            return ret;
        }

        public static int CalculateMinPathLength(CidrGraphNode node)
        {
            int ret = int.MaxValue;
            foreach (var end in node.GetEnds())
            {
                int bfslen = end.CalculateBFSLength();
                if (bfslen < ret)
                    ret = bfslen;
            }
            return ret;
        }

        public int CalculateMaxPathLength()
        {
            return CalculateMaxPathLength(Root);
        }

        public int CalculateMinPathLength()
        {
            return CalculateMinPathLength(Root);
        }

        static public CidrGraph BuildGraph(IEnumerable<IpCidr> cidrs)
        {
            CidrGraph graph = new CidrGraph();

            //Step 1 fill out an ideal graph
            graph.Root = new CidrGraphNode(null);
            PriorityQueue<CidrGraphNode> priorityQueue = new PriorityQueue<CidrGraphNode>();
            foreach (var end in graph.Root.GetNodes())
            {
                priorityQueue.Enqueue(end, end.CalculateNewChildBFSLength());
            }
            int nodesCount;
            do
            {
                var node = priorityQueue.Dequeue();
                var newNode = new CidrGraphNode(node);
                node.Children.Add(newNode);
                priorityQueue.Enqueue(node, node.CalculateNewChildBFSLength());
                priorityQueue.Enqueue(newNode, newNode.CalculateNewChildBFSLength());

                nodesCount = graph.Root.GetEnds().Count();
            } while (nodesCount != cidrs.Count());

            //Step 2 fill out graph with ideal values
            Queue<IpCidr> cidrQueue = new Queue<IpCidr>(cidrs);
            foreach (var end in graph.Root.GetEnds())
            {
                end.Cidr = cidrQueue.Dequeue();
            }

            //Step 3 fill out parent masks
            Queue<CidrGraphNode> nodeQueue = new Queue<CidrGraphNode>();
            foreach (var end in graph.Root.GetEnds())
            {
                if(end.Parent != null)
                    nodeQueue.Enqueue(end.Parent);
            }
            while (nodeQueue.Count != 0)
            {
                var node = nodeQueue.Dequeue();

                var network = node.Children.First().Cidr;

                bool loopIncomplete = true;
                while (loopIncomplete)
                {
                    loopIncomplete = false;
                    foreach (var child in node.Children)
                    {
                        if (network.Cidr == 0)
                            break;

                        if (!network.Contains(child.Cidr))
                        {
                            network.Cidr--;
                            loopIncomplete = true;
                            break;
                        }
                    }
                }

                node.Cidr = network;

                if (node.Parent != null)
                {
                    nodeQueue.Enqueue(node.Parent);
                }
            }

            //Step 4: fix over large CIDRS
            bool hasMadeChanges = false;
            do
            {
                foreach (var child in graph.Root.Children)
                {
                    nodeQueue.Enqueue(child);
                }
                while (nodeQueue.Count != 0)
                {
                    var node = nodeQueue.Dequeue();

                    if (node.Parent != null)
                    {
                        foreach (var sibling in node.Parent.Children.Where((a) => a != node))
                        {
                            if (sibling.Cidr.Contains(node.Cidr))
                            {
                                var place = sibling;

                                bool done = true;
                                while (place.Cidr.Contains(node.Cidr))
                                {
                                    foreach (var child in place.Children)
                                    {
                                        if (child.Cidr.Contains(node.Cidr))
                                        {
                                            place = child;
                                            done = false;
                                            break;
                                        }
                                    }
                                    if (done)
                                    {
                                        break;
                                    }
                                    done = true;
                                }

                                //move CIDR
                                if (sibling.Children.Count == 0)
                                {
                                    throw new Exception("Conflicting CIDR");
                                }
                                sibling.Children.Add(node);
                                node.Parent.Children.Remove(node);
                                node.Parent = sibling;
                                hasMadeChanges = true;

                                break;
                            }
                        }


                    }

                    //Do for children
                    foreach (var child in node.Children)
                    {
                        nodeQueue.Enqueue(child);
                    }
                }
                foreach (var child in graph.Root.Children)
                {
                    nodeQueue.Enqueue(child);
                }
                while (nodeQueue.Count != 0)
                {
                    var node = nodeQueue.Dequeue();

                    //Optimize graph for single item containers
                    if (node.Parent.Children.Count == 1)
                    {
                        var parent = node.Parent;
                        if (parent.Parent != null)
                        {
                            var parentIdx = parent.Parent.Children.IndexOf(parent);
                            parent.Parent.Children[parentIdx] = node;
                            node.Parent = parent;
                        }
                        else
                        {
                            graph.Root = node;
                        }
                        hasMadeChanges = true;
                    }

                    //Do for children
                    foreach (var child in node.Children)
                    {
                        nodeQueue.Enqueue(child);
                    }
                }
            } while (hasMadeChanges);

            //Step 5: order by path length to optimize what Step 4 creates
            foreach (var child in graph.Root.Children)
            {
                nodeQueue.Enqueue(child);
            }
            while (nodeQueue.Count != 0)
            {
                var node = nodeQueue.Dequeue();

                node.Children.Sort((a, b) =>
                {
                    double aLen = a.Children.Count + CalculateAveragePathLength(a);
                    double bLen = b.Children.Count + CalculateAveragePathLength(b);

                    if (aLen == bLen) return 0;
                    return (aLen > bLen)?-1:1;
                });
            }

            //Result: Not optimum but pretty damn decent!

            return graph;
        }
    }
}
