using System;
using System.Diagnostics;
using System.IO;

namespace IPTables.Net.Tests
{
    [CollectionDefinition(Name, DisableParallelization = true)]
    public class SystemIptablesCollectionDefinition
    {
        public const string Name = "System iptables";
    }

    internal static class TestEnvironment
    {
        public static bool IsLinux
        {
            get
            {
                int platform = (int)Environment.OSVersion.Platform;
                return (platform == 4) || (platform == 6) || (platform == 128);
            }
        }

        public static string GetLinuxSystemTestSkipReason()
        {
            if (!IsLinux)
            {
                return "System tests require Linux.";
            }

            if (Environment.GetEnvironmentVariable("SKIP_SYSTEM_TESTS") == "1")
            {
                return "System tests disabled via SKIP_SYSTEM_TESTS=1.";
            }

            return null;
        }

        public static void RequireLinuxSystemTests()
        {
            var skipReason = GetLinuxSystemTestSkipReason();
            if (skipReason != null)
            {
                Assert.Skip(skipReason);
            }
        }
    }

    internal static class IptablesSystemTestSupport
    {
        public const int IpVersion = 4;

        public static string GetBinaryName(int ipVersion)
        {
            return ipVersion == 4 ? "iptables" : "ip6tables";
        }

        public static string GetBinary(int ipVersion)
        {
            var name = GetBinaryName(ipVersion);
            if (Path.Exists("/sbin/" + name))
            {
                return "/sbin/" + name;
            }

            if (Path.Exists("/usr/sbin/" + name))
            {
                return "/usr/sbin/" + name;
            }

            return name;
        }

        public static int Execute(string binary, string args, bool logOutput = true)
        {
            using (var process = Process.Start(new ProcessStartInfo(binary, args)
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false
            }))
            {
                var standardOutput = process.StandardOutput.ReadToEnd();
                var standardError = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (logOutput)
                {
                    if (!string.IsNullOrWhiteSpace(standardOutput))
                    {
                        Console.WriteLine(standardOutput);
                    }

                    if (!string.IsNullOrWhiteSpace(standardError))
                    {
                        Console.Error.WriteLine(standardError);
                    }
                }

                return process.ExitCode;
            }
        }

        public static void RequireSuccess(string binary, string args)
        {
            var exitCode = Execute(binary, args);
            Assert.True(exitCode == 0, "Command should succeed: " + binary + " " + args);
        }

        public static void CleanupTestChains(string binary)
        {
            foreach (var chain in new[] { "test", "test2", "test3" })
            {
                Execute(binary, "-F " + chain, false);
                Execute(binary, "-X " + chain, false);
            }
        }
    }
}
