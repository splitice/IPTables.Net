using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IPTables.Net.Modules.Base;

namespace IPTables.Net.Modules
{
    public interface IIptablesModule
    {
        String GetRuleString();
        int Feed(RuleParser parser, bool not);
    }
}
