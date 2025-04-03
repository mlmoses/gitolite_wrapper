using System;
using System.Collections.Generic;
using System.IO;

namespace GitoliteWrapper;

internal static class Program
{
    public static int Main(string[] args)
    {
        var parsedArgs = ParseArgs(args);
        var username = string.Empty;

        if (ReadUserAuthContents(out var userAuth))
        {
            var (keyTypeRange, keyRange) = UserAuthParser.FindPublicKey(userAuth);
            if (SshPublicKeyExtensions.IsSupportedCertType(userAuth[keyTypeRange]) && userAuth[keyRange].DecodeBase64(out var key))
                username = key.FindGitoliteUser();
        }

        if (!parsedArgs.Test)
        {
            string[] shellArgs = username.Length > 0 ? [username] : [];
            // TODO: errCode and errDescription should be logged.
            var (errCode, errDescription) = Posix.Exec(parsedArgs.ShellPath, shellArgs);
            return 1;
        }

        if (username.Length == 0)
            return 1;

        Console.Out.WriteLine(username);
        return 0;
    }

    private static Args ParseArgs(IEnumerable<string> args)
    {
        var shellPath = "gitolite-shell";
        var test = false;
        var next = 0;
        foreach (var a in args)
        {
            switch (next)
            {
                case 0:
                    switch (a)
                    {
                        case "--test":
                        case "-t":
                            test = true;
                            break;
                        case "--shell":
                        case "-s":
                            next = 1;
                            break;
                    }
                    break;
                case 1:
                    if (!string.IsNullOrWhiteSpace(a))
                        shellPath = a.Trim();
                    next = 0;
                    break;
            }
        }

        return new Args(shellPath, test);
    }

    private static bool ReadUserAuthContents(out Span<byte> content)
    {
        var path = Environment.GetEnvironmentVariable("SSH_USER_AUTH");
        if (!string.IsNullOrEmpty(path))
        {
            var data = File.ReadAllBytes(path);
            if (data.Length > 0)
            {
                content = data.AsSpan();
                return true;
            }
        }

        content = Span<byte>.Empty;
        return false;
    }

    private sealed class Args(string shellPath, bool test)
    {
        public string ShellPath { get; } = shellPath;
        public bool Test { get; } = test;
    }
}
