using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Supporting;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    class LevensheteinSolutionTest
    {
        [TestCase]
        public void DistanceTest()
        {
            String s = "democrat";
            String t = "republican";

            LevenshteinSolution<char> l = new LevenshteinSolution<char>();
            var distance = l.GetDistance(s.ToCharArray(), t.ToCharArray());

            Assert.AreEqual(8, distance);
        }

        [TestCase]
        public void InstructionsTest()
        {
            String s = "democrat";
            String t = "republican";

            LevenshteinSolution<char> l = new LevenshteinSolution<char>();
            var instructions = l.GetInstructions(s.ToCharArray(), t.ToCharArray());

            var applied = l.ApplyInstructions(s.ToCharArray(), instructions);

            string tApplied = new string(applied);

            Assert.AreEqual(t, tApplied);
        }

        [TestCase]
        public void InstructionsBulkTest()
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            LevenshteinSolution<char> l = new LevenshteinSolution<char>();

            for (int i = 0; i < 100; i++)
            {
                String s = new string(
                    Enumerable.Repeat(chars, 8)
                              .Select(a => a[random.Next(a.Length)])
                              .ToArray());
                String t = new string(
                    Enumerable.Repeat(chars, 8)
                            .Select(a => a[random.Next(s.Length)])
                            .ToArray());

                var instructions = l.GetInstructions(s.ToCharArray(), t.ToCharArray());

                var applied = l.ApplyInstructions(s.ToCharArray(), instructions);

                string tApplied = new string(applied);

                Assert.AreEqual(t, tApplied);
            }
        }
    }
}
