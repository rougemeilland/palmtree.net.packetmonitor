using System;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Palmtree.Net.PacketMonitor
{
    public class TCPPacket
    {
        public TCPPacket(IPAddress srcIPAddress, IPAddress dstIPAddress, byte[] rawPacketBuffer, int index, int length)
        {
            var headerLength = (rawPacketBuffer[index + 12] >> 8) << 2;
            if (length < headerLength)
                throw new Exception();
            if (index + length > rawPacketBuffer.Length)
                throw new Exception();
            SourceEndPoint = new IPEndPoint(srcIPAddress, (rawPacketBuffer[index + 0] << 8) | rawPacketBuffer[index + 1]);
            DestinationEndPoint = new IPEndPoint(dstIPAddress, (rawPacketBuffer[index + 2] << 8) | rawPacketBuffer[index + 3]);
            ACK = (rawPacketBuffer[index + 13] & 0x10) != 0;
            RST = (rawPacketBuffer[index + 13] & 0x041) != 0;
            SYN = (rawPacketBuffer[index + 13] & 0x02) != 0;
            FIN = (rawPacketBuffer[index + 13] & 0x01) != 0;
            var dataIndex = index + headerLength;
            var dataLength = length - headerLength;
            Data = new byte[dataLength];
            Array.Copy(rawPacketBuffer, dataIndex, Data, 0, dataLength);


        }

        public IPEndPoint SourceEndPoint { get; }
        public IPEndPoint DestinationEndPoint { get; }
        public bool ACK { get; }
        public bool RST { get; }
        public bool SYN { get; }
        public bool FIN { get; }
        public byte[] Data { get; }

        public override string ToString()
        {
            var flags = "";
            if (ACK)
                flags += " ACK";
            if (RST)
                flags += " RST";
            if (SYN)
                flags += " SYN";
            if (FIN)
                flags += " FIN";
            return string.Format("src={0}, dst={1}, len={2}{3}", SourceEndPoint, DestinationEndPoint, Data.Length, flags);
        }
    }
}
