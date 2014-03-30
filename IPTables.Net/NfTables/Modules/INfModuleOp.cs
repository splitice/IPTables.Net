using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.NfTables.Modules
{
    public interface INfModuleOp
    {
        /// <summary>
        /// Can we handle this command
        /// </summary>
        /// <param name="argument"></param>
        /// <returns></returns>
        bool IsHandled(String argument);

        /// <summary>
        /// Handle a command
        /// </summary>
        /// <param name="argument"></param>
        /// <returns>the number of arguments we expect</returns>
        int HandleCommand(String argument);

        /// <summary>
        /// Handle arguments to a "command"
        /// </summary>
        /// <param name="arguments">the arguments as requested by HandleFirst</param>
        /// <returns>the number of arguments we expect</returns>
        int HandleArgument(IEnumerable<String> arguments);
    }
}
