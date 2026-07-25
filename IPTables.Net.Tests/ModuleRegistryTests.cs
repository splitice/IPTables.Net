using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Modules;

namespace IPTables.Net.Tests
{
    public class ModuleRegistryTests
    {
        [Fact]
        public void CustomTargetModulesCanRegisterAndParseConcurrently()
        {
            var exceptions = new ConcurrentQueue<Exception>();

            Parallel.For(0, 16, worker =>
            {
                try
                {
                    for (var i = 0; i < 100; i++)
                    {
                        var moduleName = $"THREADTARGET{worker}_{i}";
                        var ruleText = $"-A POSTROUTING -t mangle -j {moduleName} --thread-target-value 1";

                        ModuleRegistry.Instance.RegisterModule(ThreadTargetModule.GetModuleEntry(moduleName));

                        var rule = IpTablesRule.Parse(ruleText, null, new IpTablesChainSet(4), 4);
                        var module = rule.GetModuleOrLoad<ThreadTargetModule>(moduleName);

                        Assert.Equal(1, module.Value);
                        Assert.Equal(ruleText, rule.GetActionCommand());
                    }
                }
                catch (Exception ex)
                {
                    exceptions.Enqueue(ex);
                }
            });

            if (!exceptions.IsEmpty)
            {
                throw new AggregateException(exceptions);
            }
        }

        private sealed class ThreadTargetModule : ModuleBase, IIpTablesModule
        {
            private const string OptionValue = "--thread-target-value";

            public int Value { get; private set; }

            private ThreadTargetModule(int version) : base(version)
            {
            }

            public bool NeedsLoading => false;

            public int Feed(CommandParser parser, bool not)
            {
                if (parser.GetCurrentArg() != OptionValue)
                {
                    return 0;
                }

                Value = int.Parse(parser.GetNextArg());
                return 1;
            }

            public string GetRuleString()
            {
                return Value == 0 ? string.Empty : OptionValue + " " + Value;
            }

            public static ModuleEntry GetModuleEntry(string name)
            {
                return GetTargetModuleEntryInternal(name, typeof(ThreadTargetModule), GetOptions,
                    version => new ThreadTargetModule(version));
            }

            private static HashSet<string> GetOptions()
            {
                return new HashSet<string> { OptionValue };
            }
        }
    }
}
