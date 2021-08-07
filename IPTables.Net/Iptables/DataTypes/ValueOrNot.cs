using System;
using System.Collections.Generic;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.DataTypes
{
    public struct ValueOrNot<T> : IEquatable<ValueOrNot<T>>
    {
        private bool _not;
        private bool _hasValue;
        private T _value;

        public ValueOrNot(T value, bool not = false)
        {
            _value = value;
            _not = not;
// ReSharper disable once CompareNonConstrainedGenericWithNull
            _hasValue = value != null;
        }

        public ValueOrNot(T value, T nullValue, bool not = false)
        {
            _value = value;
            _not = not;
            _hasValue = !EqualityComparer<T>.Default.Equals(value, nullValue);
        }

        public T Value => _value;

        public bool Not
        {
            get => _not;
            set => _not = value;
        }

        public bool Null => !_hasValue;

        public bool Equals(ValueOrNot<T> other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return _not.Equals(other._not) && _hasValue.Equals(other._hasValue) &&
                   (!_hasValue || EqualityComparer<T>.Default.Equals(_value, other._value));
        }

        public void Set(bool not, T value)
        {
            _not = not;

            if (value == null)
            {
                _hasValue = false;
            }
            else
            {
                _value = value;
                _hasValue = true;
            }
        }

        public string ToOption(string optionKey, string value = null, bool escape = true)
        {
            var built = "";
            if (Null) return built;

            if (Not) built += "! ";
            built += optionKey;

            if (value == null) value = Value.ToString();

            if (escape) value = ShellHelper.EscapeArguments(value);

            if (!string.IsNullOrEmpty(value)) built += " " + value;
            return built;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((ValueOrNot<T>) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = _not.GetHashCode();
                hashCode = (hashCode * 397) ^ EqualityComparer<T>.Default.GetHashCode(_value);
                hashCode = (hashCode * 397) ^ _hasValue.GetHashCode();
                return hashCode;
            }
        }
    }
}