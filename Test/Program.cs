using System;
using System.Text;
using System.Collections.Generic;
using System.Security;
using System.Security.Principal;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
using SharpPcap;
using SharpPcap.Npcap;
using SharpPcap.WinPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using PacketDotNet.Tcp;
using PacketDotNet.Utils;
using PacketDotNet.Utils.Converters;


namespace Test
{
    class Program
    {
        private enum TransmissionDirection
        {
            None,
            Send,
            Recv,
        }

        private class TimeStampKey
            : IComparable<TimeStampKey>, IComparable
        {
            private static long _serialNumber;
            private static long _previousTimeStamp;
            private static object _lockObject;
            private long _minorOrder;
            private string _text;

            static TimeStampKey()
            {
                BaseTimeStamp = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;
                _serialNumber = 0;
                _previousTimeStamp = long.MinValue;
                _lockObject = new object();
            }

            public TimeStampKey()
            {
                var now = DateTime.UtcNow;
                Time = now;
                TimeStamp = now.Ticks - BaseTimeStamp;
                lock (_lockObject)
                {
                    if (_previousTimeStamp == TimeStamp)
                        _minorOrder = _serialNumber++;
                    else
                    {
                        _minorOrder = 0;
                        _previousTimeStamp = TimeStamp;
                        _serialNumber = 0;
                    }
                }
                _text = null;
            }
            public static long BaseTimeStamp { get; }

            public long TimeStamp { get; }

            public DateTime Time { get; }

            public override bool Equals(object o)
            {
                if (o == null || GetType() != o.GetType())
                    return false;

                var p = (TimeStampKey)o;
                if (!TimeStamp.Equals(p.TimeStamp))
                    return false;
                if (!_minorOrder.Equals(p._minorOrder))
                    return false;
                return true;
            }

            public override int GetHashCode()
            {
                return TimeStamp.GetHashCode() ^ _minorOrder.GetHashCode();
            }

            public int CompareTo(TimeStampKey o)
            {
                if (o == null)
                    return 1;
                int c;
                if ((c = TimeStamp.CompareTo(o.TimeStamp)) != 0)
                    return c;
                if ((c = _minorOrder.CompareTo(o._minorOrder)) != 0)
                    return c;
                return 0;
            }

            public int CompareTo(object o)
            {
                if (o == null)
                    return 1;

                var p = o as TimeStampKey;
                if (p == null)
                    throw new ArgumentException("Object is not a TimeStampKey");
                return CompareTo(p);
            }

            public override string ToString()
            {
                if (_text == null)
                    _text = string.Format("{0}@{1}", TimeStamp, _minorOrder);
                return _text;
            }
        }

        private class TransmittedTcpPacketEventArgs
            : EventArgs
        {
            private string _text;

            public TransmittedTcpPacketEventArgs(
                TcpConnectionId connectionId,
                TransmissionDirection direction,
                bool synchronize,
                bool acknowledgment,
                bool reset,
                bool finished,
                uint sequenceNumber,
                uint acknowledgmentNumber,
                byte[] data)
            {
                _text = null;
                TimeStampKey = new TimeStampKey();
                ConnectionId = connectionId;
                Direction = direction;
                Synchronize = synchronize;
                Acknowledgment = acknowledgment;
                Reset = reset;
                Finished = finished;
                SequenceNumber = sequenceNumber;
                AcknowledgmentNumber = acknowledgmentNumber;
                Data = new byte[data.Length];
                Array.Copy(data, Data, Data.Length);
            }

            public TimeStampKey TimeStampKey { get; }
            public TcpConnectionId ConnectionId { get; }
            public TransmissionDirection Direction { get; }

            public bool Synchronize { get; set; }
            public bool Acknowledgment { get; set; }
            public bool Reset { get; set; }
            public bool Finished { get; set; }
            public uint SequenceNumber { get; set; }
            public uint AcknowledgmentNumber { get; set; }
            public byte[] Data { get; }

            public override string ToString()
            {
                if (_text == null)
                {
                    var properties = new List<string>();
                    properties.Add(string.Format("time={0}", TimeStampKey));
                    properties.Add(string.Format("con={0}", ConnectionId));
                    string directionText;
                    switch (Direction)
                    {
                        case TransmissionDirection.Send:
                            directionText = "SND";
                            break;
                        case TransmissionDirection.Recv:
                            directionText = "RCV";
                            break;
                        default:
                            throw new Exception();
                    }
                    properties.Add(string.Format("dir={0}", directionText));
                    properties.Add(string.Format("seq={0}", SequenceNumber));
                    var flags = new List<string>();
                    if (Synchronize)
                        flags.Add("SYN");
                    if (Acknowledgment)
                        flags.Add(string.Format("ACK({0})", AcknowledgmentNumber));
                    if (Reset)
                        flags.Add("RST");
                    if (Finished)
                        flags.Add("FIN");
                    properties.Add(string.Format("flg={0}", string.Join("|", flags)));
                    properties.Add(string.Format("len={0}", Data.Length));
                    if (Data.Length > 0)
                    {
                        string dataText;
                        if (Data.Length <= 16)
                            dataText = Encoding.ASCII.GetString(Data);
                        else
                            dataText = Encoding.ASCII.GetString(Data, 0, 16) + "...";
                        dataText = string.Concat(dataText.Select(c => char.IsControl(c) ? '?' : c));
                        properties.Add(string.Format("data=\"{0}\"", dataText));
                    }
                    _text = string.Format("{{{0}}}", string.Join(", ", properties));
                }
                return _text;
            }
        }

        private class TcpConnectionId
        {
            private string _text;

            public TcpConnectionId(TransmissionDirection direction, IPAddress sourceIPAddress, IPAddress destinationIPAddress, ushort sourcePort, ushort destinationPort)
            {
                _text = null;
                switch (direction)
                {
                    case TransmissionDirection.Send:
                        RemoteEndPoint = new IPEndPoint(destinationIPAddress, destinationPort);
                        LocalPort = sourcePort;
                        break;
                    case TransmissionDirection.Recv:
                        RemoteEndPoint = new IPEndPoint(sourceIPAddress, sourcePort);
                        LocalPort = destinationPort;
                        break;
                    default:
                        throw new Exception();
                }
            }

            public IPEndPoint RemoteEndPoint { get; }
            public ushort LocalPort { get; }

            public override bool Equals(object o)
            {
                if (o == null || GetType() != o.GetType())
                    return false;
                var p = (TcpConnectionId)o;
                if (!p.RemoteEndPoint.Equals(p.RemoteEndPoint))
                    return false;
                if (!p.LocalPort.Equals(p.LocalPort))
                    return false;
                return true;
            }

            public override int GetHashCode()
            {
                return RemoteEndPoint.GetHashCode() ^ LocalPort.GetHashCode();
            }

            public override string ToString()
            {
                if (_text == null)
                    _text = string.Format("{0}@{1}@{2}", RemoteEndPoint.Address, RemoteEndPoint.Port, LocalPort);
                return _text;
            }
        }

        static void Main(string[] args)
        {


#if false
            var sockets = NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic =>
                    nic.OperationalStatus == OperationalStatus.Up &&
                    nic.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                    nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                .Select(nic => nic.GetIPProperties())
                .Where(props => props != null)
                .SelectMany(props => props.UnicastAddresses)
                .Select(unicastAddress =>
                {
                    switch (unicastAddress.Address.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            return CreateIPV4RawSocket(unicastAddress.Address);
                        case AddressFamily.InterNetworkV6:
                            return CreateIPV6RawSocket(unicastAddress.Address);
                        default:
                            return null;
                    }
                })
                .Where(socket => socket != null)
                .ToList();

            foreach (var socket in sockets)
                ReceivePacket(socket);
            Console.ReadLine();
#else
            var targetIPAddresses = new[] { IPAddress.Parse("124.150.157.49") };

            foreach (var device in CaptureDeviceList.Instance)
            {
                try
                {
                    IDictionary<IPAddress, object> intefaceAddresses;
                    bool isLoopbackDevice;
                    if (device is LibPcapLiveDevice)
                    {
                        var p = (LibPcapLiveDevice)device;
                        isLoopbackDevice = p.Loopback;
                        intefaceAddresses = p.Addresses.Where(address => address.Addr.ipAddress != null).ToDictionary(address => address.Addr.ipAddress, address => (object)null);

                    }
                    else if (device is NpcapDevice)
                    {
                        var p = (NpcapDevice)device;
                        isLoopbackDevice = p.Loopback;
                        intefaceAddresses = p.Addresses.Where(address => address.Addr.ipAddress != null).ToDictionary(address => address.Addr.ipAddress, address => (object)null);
                    }
                    else
                    {
                        throw new Exception();
                    }
                    if (!isLoopbackDevice)
                    {
                        device.OnPacketArrival += (s, e) =>
                        {
                            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                            if (packet != null)
                            {
                                var ipPacket = packet.Extract<IPPacket>();
                                if (ipPacket != null)
                                {
                                    var sourceIPAddress = ipPacket.SourceAddress;
                                    var destinationIPAddress = ipPacket.DestinationAddress;
                                    TransmissionDirection direction;
                                    if (intefaceAddresses.ContainsKey(sourceIPAddress))
                                    {
                                        if (intefaceAddresses.ContainsKey(destinationIPAddress))
                                            direction = TransmissionDirection.None;
                                        else
                                            direction = TransmissionDirection.Send;
                                    }
                                    else
                                    {
                                        if (intefaceAddresses.ContainsKey(destinationIPAddress))
                                            direction = TransmissionDirection.Recv;
                                        else
                                            direction = TransmissionDirection.None;
                                    }
                                    if (direction != TransmissionDirection.None)
                                    {
                                        var tcpPacket = packet.Extract<TcpPacket>();
                                        if (tcpPacket != null)
                                        {
                                            var sourceEndPoint = new IPEndPoint(sourceIPAddress, tcpPacket.SourcePort);
                                            var destinationEndPoint = new IPEndPoint(destinationIPAddress, tcpPacket.DestinationPort);
                                            var connectionId = new TcpConnectionId(direction, sourceIPAddress, destinationIPAddress, tcpPacket.SourcePort, tcpPacket.DestinationPort);

                                            var arg =
                                                new TransmittedTcpPacketEventArgs(
                                                    connectionId,
                                                    direction,
                                                    tcpPacket.Synchronize,
                                                    tcpPacket.Acknowledgment,
                                                    tcpPacket.Reset,
                                                    tcpPacket.Finished,
                                                    tcpPacket.SequenceNumber,
                                                    tcpPacket.AcknowledgmentNumber,
                                                    tcpPacket.PayloadData);
                                            System.Diagnostics.Debug.WriteLine(arg.ToString());
                                        }
                                    }
                                }
                            }
                        };
                        device.Open(DeviceMode.Promiscuous);
                        var addressFilters =
                            targetIPAddresses
                            .Select(address => string.Format("ip host {0}", address))
                            .ToList();
                        string filter;
                        switch (addressFilters.Count)
                        {
                            case 0:
                                filter = "(ip || ip6) && tcp";
                                break;
                            case 1:
                                filter =
                                    string.Format(
                                        "(ip || ip6) && tcp && {0}",
                                        string.Join(" || ", addressFilters.First()));
                                break;
                            default:
                                filter =
                                    string.Format(
                                        "(ip || ip6) && tcp && ({0})",
                                        string.Join(" || ", addressFilters));
                                break;
                        }
                        device.Filter = filter;
                        device.StartCapture();
                    }
                }
                catch (Exception)
                {
                    // NOP
                }
            }
            Console.ReadLine();
#endif
        }


#if false
        private static void ParseEthernetFrame(byte[] rawPacketBuffer, int length)
        {
            if (length < 14)
                throw new Exception();
            var type = (rawPacketBuffer[12] << 8) | rawPacketBuffer[13];
            switch (type)
            {
                case 0x0800:
                    ParseIPv4Packet(rawPacketBuffer, 14, length - 14);
                    break;
                case 0x86dd:
                    ParseIPv6Packet(rawPacketBuffer, 14, length - 14);
                    break;
                default:
                    break;
            }
        }
#endif

#if false
        private static Socket CreateIPV6RawSocket(IPAddress addr)
        {
            var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IP);
            socket.Bind(new IPEndPoint(addr, 0));
            socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AcceptConnection, 1);
            byte[] ib = new byte[] { 1, 0, 0, 0 };
            byte[] ob = new byte[] { 0, 0, 0, 0 };
            socket.IOControl(IOControlCode.ReceiveAll, ib, ob);//SIO_RCVALL
            return socket;
        }

        private static Socket CreateIPV4RawSocket(IPAddress addr)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            socket.Bind(new IPEndPoint(addr, 0));
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AcceptConnection, 1);
            byte[] ib = new byte[] { 1, 0, 0, 0 };
            byte[] ob = new byte[] { 0, 0, 0, 0 };
            socket.IOControl(IOControlCode.ReceiveAll, ib, ob);//SIO_RCVALL
            return socket;
        }

        private static void ReceivePacket(Socket socket)
        {
            var buf = new byte[64 * 1024];
            EndPoint remoteEndPoint1;
            switch (socket.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    remoteEndPoint1 = new IPEndPoint(IPAddress.Any, 0);
                    break;
                case AddressFamily.InterNetworkV6:
                    remoteEndPoint1 = new IPEndPoint(IPAddress.IPv6Any, 0);
                    break;
                default:
                    throw new Exception();
            }
            socket.BeginReceiveFrom(
                buf,
                0,
                buf.Length,
                SocketFlags.None,
                ref remoteEndPoint1,
                ar =>
                {
                    EndPoint remoteEndPoint2;
                    switch (socket.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            remoteEndPoint2 = new IPEndPoint(IPAddress.Any, 0);
                            break;
                        case AddressFamily.InterNetworkV6:
                            remoteEndPoint2 = new IPEndPoint(IPAddress.IPv6Any, 0);
                            break;
                        default:
                            throw new Exception();
                    }
                    var len = socket.EndReceiveFrom(ar, ref remoteEndPoint2);
                    if (len > 0)
                    {
                        switch (socket.AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                ParseIPv4Packet(buf, 0, len);
                                ReceivePacket(socket);
                                break;
                            case AddressFamily.InterNetworkV6:
                                ParseIPv6Packet(buf, 0, len);
                                ReceivePacket(socket);
                                break;
                            default:
                                throw new Exception();

                        }
                    }
                },
                null);
        }
#endif

        private static void ParseIPv4Packet(byte[] rawPacketBuffer, int index, int length)
        {
            if (length < 20)
                throw new Exception();
            if (index + length > rawPacketBuffer.Length)
                throw new Exception();
            if ((rawPacketBuffer[index + 0] & 0xf0) != 0x40)
                throw new Exception();
            var srcIPAddressBuffer = new byte[4];
            Array.Copy(rawPacketBuffer, index + 12, srcIPAddressBuffer, 0, srcIPAddressBuffer.Length);
            var srcIPAddress = new System.Net.IPAddress(srcIPAddressBuffer);
            var dstIPAddressBuffer = new byte[4];
            Array.Copy(rawPacketBuffer, index + 16, dstIPAddressBuffer, 0, dstIPAddressBuffer.Length);
            var dstIPAddress = new System.Net.IPAddress(dstIPAddressBuffer);
            int transportProtocol = rawPacketBuffer[index + 9];
            switch (transportProtocol)
            {
                case 6: // TCP
                    var headerLength = 4 * (rawPacketBuffer[index + 0] & 0x0f);
                    ParseTCPPacket(srcIPAddress, dstIPAddress, rawPacketBuffer, index + headerLength, length - headerLength);
                    break;
                case 17: // UDP
                    break;
                default:
                    break;
            }
        }

        private static void ParseIPv6Packet(byte[] rawPacketBuffer, int index, int length)
        {
            if (length < 40)
                throw new Exception();
            if (index + length > rawPacketBuffer.Length)
                throw new Exception();
            if ((rawPacketBuffer[index + 0] & 0xf0) != 0x60)
                throw new Exception();
            var srcIPAddressBuffer = new byte[16];
            Array.Copy(rawPacketBuffer, index + 8, srcIPAddressBuffer, 0, srcIPAddressBuffer.Length);
            var srcIPAddress = new System.Net.IPAddress(srcIPAddressBuffer);
            var dstIPAddressBuffer = new byte[16];
            Array.Copy(rawPacketBuffer, index + 24, dstIPAddressBuffer, 0, dstIPAddressBuffer.Length);
            var dstIPAddress = new System.Net.IPAddress(dstIPAddressBuffer);

            var nextPayloadProtocol = rawPacketBuffer[index + 6];
            var nextPayloadIndex = index + 40;
            var nextPayloadLength = length - 40;
            while (length > 0)
            {
                index = nextPayloadIndex;
                length = nextPayloadLength;
                switch (nextPayloadProtocol)
                {
                    case 6: // TCP
                        ParseTCPPacket(srcIPAddress, dstIPAddress, rawPacketBuffer, nextPayloadIndex, nextPayloadLength);
                        nextPayloadProtocol = 0xff;
                        nextPayloadIndex = rawPacketBuffer.Length;
                        nextPayloadLength = 0;
                        break;
                    case 17: // UDP
                        // NOP
                        nextPayloadProtocol = 0xff;
                        nextPayloadIndex = rawPacketBuffer.Length;
                        nextPayloadLength = 0;
                        break;
                    case 0:
                    case 60:
                        nextPayloadProtocol = rawPacketBuffer[index + 0];
                        nextPayloadIndex += rawPacketBuffer[index + 1];
                        nextPayloadLength -= rawPacketBuffer[index + 1];
                        break;
                    case 43:
                        nextPayloadProtocol = rawPacketBuffer[index + 0];
                        nextPayloadIndex += rawPacketBuffer[index + 1];
                        nextPayloadLength -= rawPacketBuffer[index + 1];
                        break;
                    case 44:
                        nextPayloadProtocol = rawPacketBuffer[index];
                        nextPayloadIndex += 8;
                        nextPayloadLength -= 8;
                        break;
                    case 139:
                        nextPayloadProtocol = rawPacketBuffer[index];
                        nextPayloadIndex += 8;
                        nextPayloadLength -= 8;
                        break;
                    case 51:
                    case 50:
                    case 135:
                    case 140:
                        throw new Exception(string.Format("unsupprted header type: {0}", nextPayloadProtocol));
                    default:
                        break;
                }
            }
        }

        private static void ParseTCPPacket(System.Net.IPAddress srcIPAddress, System.Net.IPAddress dstIPAddress, byte[] rawPacketBuffer, int index, int length)
        {
            var tcpPacket = new Palmtree.Net.PacketMonitor.TCPPacket(srcIPAddress, dstIPAddress, rawPacketBuffer, index, length);
            System.Diagnostics.Debug.WriteLine(string.Format("{0}", tcpPacket));
        }

        private static bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}