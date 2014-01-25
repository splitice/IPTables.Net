using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IPTables.Net.DataTypes
{
    public class ValueOrNot<T>
    {
        private T _value;
        private bool _not = false;
        private bool _null = true;

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
            get
            {
                return _null;
            }
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

        public String ToOption(String optionKey)
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
            built += optionKey+" ";
            built += Value;
            return built;
        }
    }
}
