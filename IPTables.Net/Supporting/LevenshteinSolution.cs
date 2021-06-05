using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace IPTables.Net.Supporting
{
    internal class LevenshteinSolution<T>
    {
        private int[,] Matrix(T[] s, T[] t)
        {
            var one = new int[1, 1];
            one[0, 0] = 0;
            if (s.Length == 0)
            {
                if (t.Length != 0) one[0, 0] = t.Length;
                return one;
            }

            if (t.Length == 0)
            {
                if (s.Length != 0) one[0, 0] = t.Length;
                return one;
            }

            var d = new int[s.Length + 1, t.Length + 1];

            for (var i = 0; i <= d.GetUpperBound(0); i += 1) d[i, 0] = i;

            for (var i = 0; i <= d.GetUpperBound(1); i += 1) d[0, i] = i;

            for (var i = 1; i <= d.GetUpperBound(0); i += 1)
            for (var j = 1; j <= d.GetUpperBound(1); j += 1)
                if (EqualityComparer<T>.Default.Equals(s[i - 1], t[j - 1]))
                    d[i, j] = d[i - 1, j - 1];
                else
                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + 1);

            return d;
        }

        public int GetDistance(T[] s, T[] t)
        {
            var d = Matrix(s, t);
            return d[d.GetUpperBound(0), d.GetUpperBound(1)];
        }

        public enum OperationType
        {
            Insertion,
            Deletion,
            Update,
            Noop
        }

        public List<OperationType> GetOperations(T[] s, T[] t)
        {
            var ops = new List<OperationType>();
            var d = Matrix(s, t);
            var currentY = d.GetUpperBound(0);
            var currentX = d.GetUpperBound(1);
            var currentValue = d[currentY, currentX];

            while (currentX != 0 && currentY != 0)
            {
                int up = int.MaxValue, left = int.MaxValue, diagonal = int.MaxValue;
                var minus1 = currentValue - 1;

                if (currentY != 0) up = d[currentY - 1, currentX];

                if (currentX != 0) left = d[currentY, currentX - 1];

                if (currentY != 0 && currentX != 0) diagonal = d[currentY - 1, currentX - 1];

                if (diagonal <= up && diagonal <= left && (diagonal == currentValue || diagonal == minus1))
                {
                    if (diagonal == minus1)
                        ops.Add(OperationType.Update);
                    else
                        ops.Add(OperationType.Noop);


                    currentY--;
                    currentX--;
                }
                else if (left <= up && (left == currentValue || left == minus1))
                {
                    ops.Add(OperationType.Insertion);
                    currentX--;
                }
                else
                {
                    ops.Add(OperationType.Deletion);
                    currentY--;
                }

                currentValue = d[currentY, currentX];
            }

            return ops;
        }

        public struct Instruction
        {
            public OperationType Op;
            public T Value;

            public Instruction(OperationType op, T val)
            {
                Op = op;
                Value = val;
            }
        }

        public List<Instruction> GetInstructions(T[] s, T[] t)
        {
            var instructions = new List<Instruction>();

            var ops = GetOperations(s, t);
            var iT = t.Length - 1;

            foreach (var o in ops)
            {
                Debug.Assert(iT >= 0);
                switch (o)
                {
                    case OperationType.Noop:
                    case OperationType.Deletion:
                        instructions.Add(new Instruction(o, default));
                        break;
                    case OperationType.Insertion:
                        instructions.Add(new Instruction(o, t[iT]));
                        break;
                    case OperationType.Update:
                        instructions.Add(new Instruction(o, t[iT]));
                        break;
                }

                iT--;
            }

            Debug.Assert(iT == -1);

            return instructions;
        }

        public T[] ApplyInstructions(T[] source, List<Instruction> instructions)
        {
            var newArray = new List<T>(source);
            var iT = source.Length - 1;
            foreach (var i in instructions)
            {
                Debug.Assert(iT >= 0);
                switch (i.Op)
                {
                    case OperationType.Noop:
                        break;
                    case OperationType.Deletion:
                        newArray.RemoveAt(iT);
                        break;
                    case OperationType.Insertion:
                        newArray.Insert(iT, i.Value);
                        break;
                    case OperationType.Update:
                        newArray[iT] = i.Value;
                        break;
                }

                iT--;
            }

            Debug.Assert(iT == -1);
            Debug.Assert(source.Length == newArray.Count);

            return newArray.ToArray();
        }
    }
}