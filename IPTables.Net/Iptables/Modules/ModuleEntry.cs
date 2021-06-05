using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;

namespace IPTables.Net.Iptables.Modules
{
    public struct ModuleEntry
    {
        public bool IsTarget;

        public Type Module
        {
            get => _module;
            set
            {
                _module = value;
                Activator = GetActivator(value);
            }
        }

        public ObjectActivator Activator;
        public string Name;
        public IEnumerable<string> Options;
        public bool Polyfill;
        public bool Preloaded;
        public bool Duplicated;
        private Type _module;

        public delegate IIpTablesModule ObjectActivator(params object[] args);

        public static ObjectActivator GetActivator(Type ctor)
        {
            return GetActivator(ctor.GetConstructors().First());
        }

        private static ObjectActivator GetActivator(ConstructorInfo ctor)
        {
            var type = ctor.DeclaringType;
            var paramsInfo = ctor.GetParameters();

            //create a single param of type object[]
            var param =
                Expression.Parameter(typeof(object[]), "args");

            var argsExp =
                new Expression[paramsInfo.Length];

            //pick each arg from the params array 
            //and create a typed expression of them
            for (var i = 0; i < paramsInfo.Length; i++)
            {
                Expression index = Expression.Constant(i);
                var paramType = paramsInfo[i].ParameterType;

                Expression paramAccessorExp =
                    Expression.ArrayIndex(param, index);

                Expression paramCastExp =
                    Expression.Convert(paramAccessorExp, paramType);

                argsExp[i] = paramCastExp;
            }

            //make a NewExpression that calls the
            //ctor with the args we just created
            var newExp = Expression.New(ctor, argsExp);

            //create a lambda with the New
            //Expression as body and our param object[] as arg
            var lambda =
                Expression.Lambda(typeof(ObjectActivator), newExp, param);

            //compile it
            var compiled = (ObjectActivator) lambda.Compile();
            return compiled;
        }
    }
}