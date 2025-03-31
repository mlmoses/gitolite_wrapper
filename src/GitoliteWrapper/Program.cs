using System;
using System.IO;
using System.Linq;

namespace GitoliteWrapper;

internal static class Program
{
    // TODO: Don't hardcode the path to gitolite-shell.
    private const string GitoliteShellPath = "/usr/bin/gitolite-shell";

    private static readonly ByteString[] CertTypes =
    [
        (ByteString)"ssh-rsa-cert-v01@openssh.com"u8,
        (ByteString)"ssh-dss-cert-v01@openssh.com"u8,
        (ByteString)"ecdsa-sha2-nistp256-cert-v01@openssh.com"u8,
        (ByteString)"ecdsa-sha2-nistp384-cert-v01@openssh.com"u8,
        (ByteString)"ecdsa-sha2-nistp521-cert-v01@openssh.com"u8,
        (ByteString)"ssh-ed25519-cert-v01@openssh.com"u8,
    ];

    public static int Main(string[] args)
    {
        var parseOnly = args.Any(a => a is "-t" or "--test");
        var userAuth = ReadUserAuthContents();

        var shellArgs = Array.Empty<string>();
        if (userAuth != null)
        {
            var (keyType, key) = UserAuthParser.FindPublicKey(userAuth);
            if (CertTypes.Any(certType => certType == keyType)) {
                // TODO: Parse the key to find the Gitolite user.
                Console.Out.WriteLine($"TODO: parse key of type: {keyType}");
            }
        }

        if (!parseOnly)
        {
            // TODO: errCode and errDescription should be logged.
            var (errCode, errDescription) = Posix.Exec(GitoliteShellPath, shellArgs);
            return 1;
        }

        if (shellArgs.Length < 1)
            return 1;

        Console.Out.WriteLine(shellArgs[0]);
        return 0;
    }

    private static ByteString? ReadUserAuthContents()
    {
        var sshUserAuth = Environment.GetEnvironmentVariable("SSH_USER_AUTH");
        if (string.IsNullOrEmpty(sshUserAuth))
            return null;

        FileStream? stream = null;
        try
        {
            stream = new FileStream(sshUserAuth, FileMode.Open, FileAccess.Read, FileShare.None);
            return ByteString.From(stream);
        }
        catch
        {
            // TODO: Log this exception.
            return null;
        }
        finally
        {
            stream?.Dispose();
        }
    }
}