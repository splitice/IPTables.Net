using System;

namespace IPTables.Net.IpSet
{
    /*
    list:set
    hash:net,iface
    hash:net,iface
    hash:net,port
    hash:net,port
    hash:net,port
    hash:net
    hash:net
    hash:net
    hash:ip,port,net
    hash:ip,port,net
    hash:ip,port,net
    hash:ip,port,ip
    hash:ip,port
    hash:ip
    bitmap:port
    bitmap:ip,mac
    bitmap:ip
    */

    [Flags]
    public enum IpSetType
    {
        Bitmap = 1, //bitmap:port
        Hash = 2, //hash:net
        Net = 4,
        Port = 8,
        Ip = 16,
        Ip2 = 32,
        CtHash = 64,
        Flag = 128
    }
}