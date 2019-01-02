using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace DNSTap
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting DNS Tap...");
            Console.WriteLine();

            string ForwardingDNS = "8.8.8.8";
            IPEndPoint ipeForwarder = new IPEndPoint(IPAddress.Parse(ForwardingDNS), 53);

            UdpClient udpClient = new UdpClient(53,AddressFamily.InterNetwork);
            
            Dictionary<UInt16, IPEndPoint> Queries = new Dictionary<ushort, IPEndPoint>();
            while (true)
            {
                try
                {
                    IPEndPoint ipeData = new IPEndPoint(0, 0);
                    byte[] bData = udpClient.Receive(ref ipeData);
                    DNSPacket dPacket = new DNSPacket(bData);
                    UInt16 RequestID = BitConverter.ToUInt16(bData, 0);

                    bool bRequest = (int)bData[2] < 128;
                    Console.Write((int)bData[2]);
                    if (bRequest)
                    {
                        udpClient.Send(bData, bData.Length, ipeForwarder);
                        if (!Queries.ContainsKey(RequestID))
                            Queries.Add(RequestID, ipeData);
                        else
                            Queries[RequestID] = ipeData;

                        Console.WriteLine("{0}>>{1} [{3}]", ipeData.ToString(), ipeForwarder.ToString(), RequestID, dPacket.QuestionRecords[0].QName);
                    }
                    else
                    {
                        udpClient.Send(bData, bData.Length, Queries[RequestID]);
                        Console.WriteLine("{0}<<{1}[{3}]", Queries[RequestID], ipeForwarder.ToString(), RequestID, dPacket.QuestionRecords[0].QName);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
            





        }
    }
}
