using System.Collections.Generic;

namespace IPTables.Net.Common
{
    internal static class DictionaryExtension
    {
        public static bool DictionaryEqual<TKey, TValue>(this IDictionary<TKey, TValue> first,
            IDictionary<TKey, TValue> second)
        {
            if (first == second) return true;
            if ((first == null) || (second == null)) 
                return false;
            if (first.Count != second.Count) 
                return false;

            EqualityComparer<TValue> comparer = EqualityComparer<TValue>.Default;

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
    }
}