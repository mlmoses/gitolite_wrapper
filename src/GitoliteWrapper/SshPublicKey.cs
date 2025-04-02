using System;
using System.Linq;

namespace GitoliteWrapper;

internal static class SshPublicKey
{
    private enum CertType
    {
        None = -1,
        Rsa,
        Dsa,
        Ecdsa256,
        Ecdsa384,
        Ecdsa521,
        Ed25519
    }

    private static readonly ByteString[] CertTypes =
    [
        (ByteString)"ssh-rsa-cert-v01@openssh.com"u8,
        (ByteString)"ssh-dss-cert-v01@openssh.com"u8,
        (ByteString)"ecdsa-sha2-nistp256-cert-v01@openssh.com"u8,
        (ByteString)"ecdsa-sha2-nistp384-cert-v01@openssh.com"u8,
        (ByteString)"ecdsa-sha2-nistp521-cert-v01@openssh.com"u8,
        (ByteString)"ssh-ed25519-cert-v01@openssh.com"u8,
    ];

    private static readonly ByteString PrincipalPrefix = (ByteString)"gitolite:"u8;

    public static bool IsSupportedCertType(ByteString type) => CertTypes.Any(t => type == t);

    public static string FindGitoliteUser(ByteString publicKey)
    {
        ByteString principals;
        var typeString = publicKey.ReadSshString(0);
        var offset = typeString.Length + 4;
        switch ((CertType)Array.IndexOf(CertTypes, typeString))
        {
            case CertType.None:
                var decodedTypeString = typeString.Decode();
                throw new ArgumentException($"Key type {decodedTypeString} not supported.");
            case CertType.Dsa:
                principals = publicKey.ReadPrincipalsFromDsa(offset);
                break;
            case CertType.Ecdsa256:
            case CertType.Ecdsa384:
            case CertType.Ecdsa521:
                principals = publicKey.ReadPrincipalsFromEcdsa(offset);
                break;
            case CertType.Ed25519:
                principals = publicKey.ReadPrincipalsFromEd25519(offset);
                break;
            case CertType.Rsa:
                principals = publicKey.ReadPrincipalsFromRsa(offset);
                break;
            default:
                throw new NotSupportedException("Unknown certificate type value.");
        }

        if (principals.IsEmpty)
            return string.Empty;

        offset = 0;
        do
        {
            var p = principals.ReadSshString(offset);
            offset = offset + 4 + p.Length;

            if (p.StartsWith(PrincipalPrefix) && p.Length > PrincipalPrefix.Length)
                return p.Decode(PrincipalPrefix.Length, p.Length - PrincipalPrefix.Length);
        } while (offset < principals.Length);

        return string.Empty;
    }

    private static ByteString ReadPrincipalsFromDsa(this ByteString publicKey, int offset)
    {
        /*
         * string    "ssh-dss-cert-v01@openssh.com"
         * string    nonce
         * mpint     p
         * mpint     q
         * mpint     g
         * mpint     y
         * uint64    serial
         * uint32    type
         * string    key id
         * string    valid principals
         * uint64    valid after
         * uint64    valid before
         * string    critical options
         * string    extensions
         * string    reserved
         * string    signature key
         * string    signature
         */

        // string nonce
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // mpint p
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // mpint q
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // mpint g
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // mpint y
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // uint64 serial
        // uint32 type
        offset += 12;
        // string key id
        offset += publicKey.ReadSshStringLength(offset) + 4;

        // string valid principals
        return publicKey.ReadSshString(offset);
    }

    private static ByteString ReadPrincipalsFromEcdsa(this ByteString publicKey, int offset)
    {
        /*
         * string    "ecdsa-sha2-nistp256-cert-v01@openssh.com" |
         *           "ecdsa-sha2-nistp384-cert-v01@openssh.com" |
         *           "ecdsa-sha2-nistp521-cert-v01@openssh.com"
         * string    nonce
         * string    curve
         * string    public_key
         * uint64    serial
         * uint32    type
         * string    key id
         * string    valid principals
         * uint64    valid after
         * uint64    valid before
         * string    critical options
         * string    extensions
         * string    reserved
         * string    signature key
         * string    signature
         */

        // string nonce
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // string curve
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // string public_key
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // uint64 serial
        // uint32 type
        offset += 12;
        // string key id
        offset += publicKey.ReadSshStringLength(offset) + 4;

        // string valid principals
        return publicKey.ReadSshString(offset);
    }

    private static ByteString ReadPrincipalsFromEd25519(this ByteString publicKey, int offset)
    {
        /*
         * string    "ssh-ed25519-cert-v01@openssh.com"
         * string    nonce
         * string    pk
         * uint64    serial
         * uint32    type
         * string    key id
         * string    valid principals
         * uint64    valid after
         * uint64    valid before
         * string    critical options
         * string    extensions
         * string    reserved
         * string    signature key
         * string    signature
         */
        
        // string nonce
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // string pk
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // uint64 serial
        // uint32 type
        offset += 12;
        // string key id
        offset += publicKey.ReadSshStringLength(offset) + 4;

        // string valid principals
        return publicKey.ReadSshString(offset);
    }

    private static ByteString ReadPrincipalsFromRsa(this ByteString publicKey, int offset)
    {
        /*
         * string    "ssh-rsa-cert-v01@openssh.com"
         * string    nonce
         * mpint     e
         * mpint     n
         * uint64    serial
         * uint32    type
         * string    key id
         * string    valid principals
         * uint64    valid after
         * uint64    valid before
         * string    critical options
         * string    extensions
         * string    reserved
         * string    signature key
         * string    signature
         */

        // string nonce
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // mpint e
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // mpint n
        offset += publicKey.ReadSshStringLength(offset) + 4;
        // uint64 serial
        // uint32 type
        offset += 12;
        // string key id
        offset += publicKey.ReadSshStringLength(offset) + 4;

        // string valid principals
        return publicKey.ReadSshString(offset);
    }

    private static int ReadSshStringLength(this ByteString publicKey, int offset) =>
        ((publicKey[offset] & 255) << 24)
        | ((publicKey[offset + 1] & 255) << 16)
        | ((publicKey[offset + 2] & 255) << 8)
        | (publicKey[offset + 3] & 255);

    private static ByteString ReadSshString(this ByteString publicKey, int offset) =>
        publicKey.Slice(offset + 4, publicKey.ReadSshStringLength(offset));
}