using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using IPTables.Net.System.Interface;
using Renci.SshNet;

namespace IPTables.Net.Remote.System
{
    class SshFactory
    {
        private readonly SshClient _connection;

        public SshFactory(String host, String username, String password)
        {
            _connection = new SshClient(host, username, password);
            _connection.Connect();
        }
        public ISystemProcess StartProcess(String command, String arguments)
        {
            return Remote.SshProcess.Start(new ProcessStartInfo(command, arguments), _connection);
        }
    }
}
