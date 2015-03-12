using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.IpSet
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

    public enum IpSetType
    {
        BitmapPort, //bitmap:port
        HashIp, //hash:ip
        HashIpPort //hash:ip,port
    }
}
