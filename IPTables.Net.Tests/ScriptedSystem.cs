using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using SystemInteract;
using IPTables.Net.TestFramework;

namespace IPTables.Net.Tests;

internal sealed class ScriptedSystem : ISystemFactory
{
    internal record Reply(string Output = "", string Error = "", int Exit = 0);
    internal record Call(string Binary, string Arguments, MemoryStream Input, MockIptablesSystemProcess Process)
    {
        public string Text => Encoding.UTF8.GetString(Input.ToArray());
    }
    public readonly List<Call> Calls = new();
    public Func<string, string, Reply> Respond = (_, _) => new();
    public ISystemProcess StartProcess(string command, string arguments)
    {
        var reply = Respond(command, arguments);
        var input = new MemoryStream();
        var process = new MockIptablesSystemProcess(Reader(reply.Output), Reader(reply.Error), reply.Exit,
            new StreamWriter(input, new UTF8Encoding(false)));
        Calls.Add(new(command, arguments, input, process));
        return process;
    }
    private static StreamReader Reader(string text) => new(new MemoryStream(Encoding.UTF8.GetBytes(text)));
    public Stream Open(string path, FileMode mode, FileAccess access) => throw new NotSupportedException();
}
