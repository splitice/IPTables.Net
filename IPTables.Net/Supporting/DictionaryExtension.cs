using System.Collections.Generic;
using System.Diagnostics;
using IPTables.Net.IpSet;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Supporting
{
    internal static class DictionaryExtension
    {
        public static bool DictionaryEqual<TKey, TValue>(this IDictionary<TKey, TValue> first,
            IDictionary<TKey, TValue> second)
        {
            if (first == second) return true;
            if (first == null || second == null)
                return false;
            if (first.Count != second.Count)
                return false;

            var comparer = EqualityComparer<TValue>.Default;

            foreach (var kvp in first)
            {
                TValue secondValue;
                if (!second.TryGetValue(kvp.Key, out secondValue))
                    return false;
                if (!comparer.Equals(kvp.Value, secondValue))
                    return false;
            }

            return true;
        }

        public static TKey DictionaryDiffering<TKey, TValue>(this IDictionary<TKey, TValue> first,
            IDictionary<TKey, TValue> second, EqualityComparer<TValue> comparer)
        {
            if (ReferenceEquals(first, second)) return default;

            foreach (var kvp in first)
            {
                TValue secondValue;
                if (!second.TryGetValue(kvp.Key, out secondValue))
                    return kvp.Key;
                if (!comparer.Equals(kvp.Value, secondValue))
                    return kvp.Key;
            }

            foreach (var kvp in second)
            {
                TValue secondValue;
                if (!first.ContainsKey(kvp.Key))
                    return kvp.Key;
            }

            return default;
        }

        public static TKey DictionaryDiffering<TKey, TValue>(this IDictionary<TKey, TValue> first,
            IDictionary<TKey, TValue> second)
        {
            return first.DictionaryDiffering(second, EqualityComparer<TValue>.Default);
        }

        public static bool FindCidr<TValue>(this IDictionary<IpCidr, TValue> dict, IpCidr findOriginal, out IpCidr o,
            out TValue f)
        {
            for (var i = findOriginal.Prefix; i != 0; i++)
            {
                var find = IpCidr.NewRebase(findOriginal.Address, i);
                if (dict.TryGetValue(find, out f))
                {
                    Debug.Assert(find.Equals(findOriginal) || find.Contains(findOriginal));
                    o = find;
                    return true;
                }
            }

            o = default;
            f = default;

            return false;
        }

        public static bool FindCidr<TValue>(this IDictionary<IpSetEntry, TValue> dict, IpSetEntry findOriginal,
            out IpSetEntry o, out TValue f)
        {
            var find = new IpSetEntry(findOriginal.Set, findOriginal.Cidr, findOriginal.Protocol, findOriginal.Port,
                findOriginal.Mac);
            for (var i = find.Cidr.Prefix; i != 0; i--)
            {
                find.Cidr = IpCidr.NewRebase(find.Cidr.Address, i);
                if (dict.TryGetValue(find, out f))
                {
                    Debug.Assert(find.Cidr.Equals(findOriginal.Cidr) || find.Cidr.Contains(findOriginal.Cidr));
                    o = find;
                    return true;
                }
            }

            o = default;
            f = default;

            return false;
        }
    }
}