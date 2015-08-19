//#define DEBUG_NATIVE_IPTCP
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables.NativeLibrary
{
    public class IptcInterface
    {
        private IntPtr _handle;
        public const String Library = "libip4tc.so";
        public const String Helper = "libipthelper.so";
        public const int StringLabelLength = 32;

        public const String IPTC_LABEL_ACCEPT = "ACCEPT";
        public const String IPTC_LABEL_DROP = "DROP";
        public const String IPTC_LABEL_QUEUE = "QUEUE";
        public const String IPTC_LABEL_RETURN = "RETURN";

        /* Does this chain exist? */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_is_chain(String chain, IntPtr handle);

        /* Take a snapshot of the rules.  Returns NULL on error. */
        [DllImport(Library, SetLastError = true)]
        public static extern IntPtr iptc_init(String tablename);

        /* Cleanup after iptc_init(). */
        [DllImport(Library, SetLastError = true)]
        public static extern void iptc_free(IntPtr h);

        /* Iterator functions to run through the chains.  Returns NULL at end. */
        [DllImport(Library, SetLastError = true)]
        public static extern IntPtr iptc_first_chain(IntPtr handle);
        [DllImport(Library, SetLastError = true)]
        public static extern IntPtr iptc_next_chain(IntPtr handle);

        /* Get first rule in the given chain: NULL for empty chain. */
        [DllImport(Library, SetLastError = true)]
        public static extern IntPtr iptc_first_rule(String chain,
                            IntPtr handle);

        /* Returns NULL when rules run out. */
        [DllImport(Library, SetLastError = true)]
        public static extern IntPtr iptc_next_rule(IntPtr prev,
                               IntPtr handle);

        /* Returns a pointer to the target name of this entry. */
        [DllImport(Library, SetLastError = true)]
        public static extern String iptc_get_target(IntPtr e,
                        IntPtr handle);

        /* Is this a built-in chain? */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_builtin(String chain, IntPtr handle);

        /* Get the policy of a given built-in chain */
        [DllImport(Library, SetLastError = true)]
        public static extern String iptc_get_policy(String chain,
                        IntPtr counter,
                        IntPtr handle);

        /* These functions return TRUE for OK or 0 and set errno.  If errno ==
           0, it means there was a version error (ie. upgrade libiptc). */
        /* Rule numbers start at 1 for the first rule. */

        /* Insert the entry `e' in chain `chain' into position `rulenum'. */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_insert_entry(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)] String chain,
                      IntPtr e,
                      uint rulenum,
                      IntPtr handle);

        /* Atomically replace rule `rulenum' in `chain' with `e'. */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_replace_entry([MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                       IntPtr e,
                       uint rulenum,
                       IntPtr handle);

        /* Append entry `e' to chain `chain'.  Equivalent to insert with
           rulenum = length of chain. */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_append_entry(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                      IntPtr e,
                      IntPtr handle);

        /* Delete the first rule in `chain' which matches `e', subject to
           matchmask (array of length == origfw) */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_delete_entry(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                      IntPtr origfw,
                      String matchmask,
                      IntPtr handle);

        /* Delete the rule in position `rulenum' in `chain'. */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_delete_num_entry(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                      uint rulenum,
                      IntPtr handle);

        /* Check the packet `e' on chain `chain'.  Returns the verdict, or
           NULL and sets errno. */
        /*[DllImport(Library, SetLastError = true)]
        public static extern String iptc_check_packet(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                          IntPtr entry,
                          IntPtr handle);*/

        /* Flushes the entries in the given chain (ie. empties chain). */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_flush_entries(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                       IntPtr handle);

        /* Zeroes the counters in a chain. */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_zero_entries(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                      IntPtr handle);

        /* Creates a new chain. */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_create_chain(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                      IntPtr handle);

        /* Deletes a chain. */
        [DllImport(Library, SetLastError = true)]
        static extern int iptc_delete_chain(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                      IntPtr handle);

        /* Renames a chain. */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_rename_chain(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                      IntPtr handle);

        /* Sets the policy on a built-in chain. */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_set_policy(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chainPolicy,
                    IntPtr counters,
                    IntPtr handle);

        /* Get the number of references to this chain */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_get_references(IntPtr references,
                [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                    IntPtr handle);

        /* read packet and byte counters for a specific rule */
        [DllImport(Library, SetLastError = true)]
        public static extern IntPtr iptc_read_counter(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                               uint rulenum,
                               IntPtr handle);

        /* zero packet and byte counters for a specific rule */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_zero_counter(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                      uint rulenum,
                      IntPtr handle);

        /* set packet and byte counters for a specific rule */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_set_counter(
            [MarshalAs(UnmanagedType.LPStr, SizeConst = StringLabelLength)]
                String chain,
                     uint rulenum,
                     IntPtr counters,
                     IntPtr handle);

        /* Makes the actual changes. */
        [DllImport(Library, SetLastError = true)]
        public static extern int iptc_commit(IntPtr handle);

        /* Get raw socket. */
        /*[DllImport(Library, SetLastError = true)]
        public static extern int iptc_get_raw_socket();*/

        /* Translates errno numbers into more human-readable form than strerror. */
        [DllImport(Library, SetLastError = true)]
        public static extern IntPtr iptc_strerror(int err);

        [DllImport(Helper, SetLastError = true)]
        public static extern IntPtr output_rule4(IntPtr e, IntPtr h, String chain, int counters);

        [DllImport(Helper, SetLastError = true)]
        public static extern int execute_command(String command, IntPtr h);

        [DllImport(Helper, SetLastError = true)]
        public static extern int init_helper();

        [DllImport(Helper, SetLastError = true)]
        static extern IntPtr init_handle(String table);

        [DllImport(Helper)]
        static extern String last_error();

        private static bool _helperInit = false;

        public static bool DllExists(out String msg)
        {
            try
            {
                Marshal.PrelinkAll(typeof (IptcInterface));
            }
            catch (DllNotFoundException ex)
            {
                msg = ex.Message;
                return false;
            }
            msg = null;
            return true;
        }

        public static bool DllExists()
        {
            String msg;
            return DllExists(out msg);
        }

        public IptcInterface(String table)
        {
            if (!_helperInit)
            {
                if (init_helper() < 0)
                {
                    throw new Exception("Failed to initialize the helper / xtables");
                }
                _helperInit = true;
            }
            OpenTable(table);
        }

        ~IptcInterface()
        {
            if (_handle != IntPtr.Zero)
            {
                Free();
            }
        }

#if DEBUG_NATIVE_IPTCP
        private List<String> _debugEntries = new List<string>(); 
#endif

        private void DebugEntry(string message)
        {
#if DEBUG_NATIVE_IPTCP
            _debugEntries.Add(message);
#endif
        }

        private void RequireHandle()
        {
            if (_handle == IntPtr.Zero)
            {
                throw new IpTablesNetException("No IP Table currently open");
            }
        }

        public void Free()
        {
            RequireHandle();
            iptc_free(_handle);
            _handle = IntPtr.Zero;
        }

        public void OpenTable(String table)
        {
            if (_handle != IntPtr.Zero)
            {
                throw new IpTablesNetException("A table is already open, commit or discard first");
            }
            _handle = init_handle(table);
        }

        public List<IntPtr> GetRules(String chain)
        {
            RequireHandle();
            List<IntPtr> ret = new List<IntPtr>();
            var rule = iptc_first_rule(chain, _handle);
            while (rule != IntPtr.Zero)
            {
                ret.Add(rule);
                rule = iptc_next_rule(rule, _handle);
            }
            return ret;
        }


        public List<string> GetChains()
        {
            RequireHandle();
            List<string> ret = new List<string>();
            var chain = iptc_first_chain(_handle);
            while (chain != IntPtr.Zero)
            {
                ret.Add(Marshal.PtrToStringAnsi(chain));
                chain = iptc_next_chain(_handle);
            }
            return ret;
        }

        public int GetLastError()
        {
            return Marshal.GetLastWin32Error();
        }

        public String GetErrorString()
        {
            int lastError = GetLastError();
            var error = iptc_strerror(lastError);
            return String.Format("({0}) {1}",lastError,Marshal.PtrToStringAnsi(error));
        }


        public String GetRuleString(String chain, IntPtr rule, bool counters = false)
        {
            RequireHandle();
            var ptr = output_rule4(rule, _handle, chain, counters ? 1 : 0);
            if (ptr == IntPtr.Zero)
            {
                throw new IpTablesNetException("IPTCH Error: " + last_error());
            }
            return Marshal.PtrToStringAnsi(ptr);
        }

        /// <summary>
        /// Insert a rule
        /// </summary>
        /// <param name="chain"></param>
        /// <param name="entry"></param>
        /// <param name="at"></param>
        /// <returns></returns>
        public bool Insert(String chain, IntPtr entry, uint at)
        {
            RequireHandle();
            return iptc_insert_entry(chain, entry, at, _handle) == 1;
        }

        /// <summary>
        /// Execute an IPTables command (add, remove, delete insert)
        /// </summary>
        /// <param name="command"></param>
        /// <returns>returns 1 for sucess, error code otherwise</returns>
        public int ExecuteCommand(string command)
        {
            DebugEntry(command);
            RequireHandle();
            var ptr = execute_command(command, _handle);

            if (ptr == 0)
            {
                throw new IpTablesNetException("IPTCH Error: "+last_error());
            }

            return ptr;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>if sucessful</returns>
        public bool Commit()
        {
            RequireHandle();
#if DEBUG_NATIVE_IPTCP
            Console.WriteLine("Commiting - ");
            foreach (var c in _debugEntries)
            {
                Console.WriteLine(c);
            }
#endif
            bool status =  iptc_commit(_handle) == 1;
            if (!status)
            {
                Free();
            }
            else
            {
                //Commit includes free
                _handle = IntPtr.Zero;
            }
            return status;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="chainName"></param>
        /// <returns>if chain exists</returns>
        public bool HasChain(string chainName)
        {
            RequireHandle();
            return iptc_is_chain(chainName, _handle) == 1;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="chainName"></param>
        /// <returns>if sucessful</returns>
        public bool AddChain(string chainName)
        {
            RequireHandle();
            return iptc_create_chain(chainName, _handle) == 1;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="chainName"></param>
        /// <returns>if sucessful</returns>
        public bool DeleteChain(string chainName)
        {
            RequireHandle();
            return iptc_delete_chain(chainName, _handle) == 1;
        }
    }
}
