using System;
using System.IO;

namespace IPTables.Net.System
{
    internal class SystemSsh
    {
        public static SystemSsh Instance = new SystemSsh();
        private readonly SshClient _client;
        private readonly SftpClient _sftp;

        private SystemSsh()
        {
            _client = new SshClient("us3.ddos.x4b.org", "root", "hackedchange");
            _client.Connect();
            _sftp = new SftpClient(_client.ConnectionInfo);
            _sftp.Connect();
        }

        public SshCommand Execute(String command)
        {
            return _client.RunCommand(command);
        }

        public Stream Open(string path, FileMode mode, FileAccess access)
        {
            return new SystemFileStream(_sftp.Open(path, mode, access));
        }
    }
}