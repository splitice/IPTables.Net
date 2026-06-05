using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Tests
{
    public class FlexibleUInt32Tests
    {
        [Fact]
        public void Parse_AcceptsDecimalAndHex()
        {
            Assert.Equal(16777984u, FlexibleUInt32.Parse("16777984"));
            Assert.Equal(16777984u, FlexibleUInt32.Parse("0x1000300"));
        }
    }
}
