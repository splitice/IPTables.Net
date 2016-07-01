using System;
using System.Collections.Generic;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.DataTypes
{
    public class ValueOrNot<T> : IEquatable<ValueOrNot<T>>
    {
        private bool _not;
        private bool _null = true;
        private T _value;

        public ValueOrNot(T value, bool not = false)
        {
            _value = value;
            _not = not;
// ReSharper disable once CompareNonConstrainedGenericWithNull
            _null = value == null;
        }

        public ValueOrNot()
        {
            _null = true;
        }

        public ValueOrNot(T value, T nullValue, bool not = false)
        {
            _value = value;
            _not = not;
            _null = EqualityComparer<T>.Default.Equals(value, nullValue);
        }

        public T Value
        {
            get { return _value; }
        }

        public bool Not
        {
            get { return _not; }
            set { _not = value; }
        }

        public bool Null
        {
            get { return _null; }
        }

        public bool Equals(ValueOrNot<T> other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return _not.Equals(other._not) && _null.Equals(other._null) &&
                   (_null || EqualityComparer<T>.Default.Equals(_value, other._value));
        }

        public void Set(bool not, T value)
        {
            _not = not;

            if (value == null)
            {
                _null = true;
            }
            else
            {
                _value = value;
                _null = false;
            }
        }

        public String ToOption(String optionKey, String value = null, bool escape = true)
        {
            String built = "";
            if (Null)
            {
                return built;
            }

            if (Not)
            {
                built += "! ";
            }
            built += optionKey;

            if (value == null)
            {
                value = Value.ToString();
            }

            if (escape)
            {
                value = ShellHelper.EscapeArguments(value);
            }

            if (!String.IsNullOrEmpty(value))
            {
                built += " " + value;
            }
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
                int hashCode = _not.GetHashCode();
                hashCode = (hashCode*397) ^ EqualityComparer<T>.Default.GetHashCode(_value);
                hashCode = (hashCode*397) ^ _null.GetHashCode();
                return hashCode;
            }
        }
    }
}