using System;
using System.IO;
using System.Net;
using System.Text;
using System.Net.Sockets;
using System.Xml.Serialization;
using System.Threading;
using System.Collections;
using System.Net.Security;
using System.Web;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Reflection;
using OpenMetaverse;
using OpenMetaverse.StructuredData;
using log4net;
using Nini.Config;
using Nwc.XmlRpc;
using OpenSim.Framework;
using Mono.Addins;

using OpenSim.Framework.Capabilities;
using OpenSim.Framework.Servers;
using OpenSim.Framework.Servers.HttpServer;
using OpenSim.Region.Framework.Interfaces;
using OpenSim.Region.Framework.Scenes;
using Caps = OpenSim.Framework.Capabilities.Caps;
using System.Text.RegularExpressions;
using OpenSim.Server.Base;
using OpenSim.Services.Interfaces;
using OSDMap = OpenMetaverse.StructuredData.OSDMap;

// Namespace where the class belongs
namespace OpenSim.Region.OptionalModules.Avatar.Voice.TCPServerVoice
{
    // TCPClient class for handling TCP connections
    public class TCPClient
    {
        // Constructor that takes a server address and port
        public TCPClient(String server, int port)
        {
            this.m_Server = server;
            this.m_Port = port;

            // Event handlers for various events
            this.ExceptionAppeared += new DelegateException(this.OnExceptionAppeared);
            this.ClientConnected += new DelegateConnection(this.OnConnected);
            this.ClientDisconnected += new DelegateConnection(this.OnDisconnected);
        }

        // TCP client variables
        public TcpClient Client;
        NetworkStream m_NetStream;
        byte[] m_ByteBuffer;
        String m_Server;
        int m_Port;
        bool m_AutoConnect = false;
        private System.Threading.Timer m_TimerAutoConnect;
        private int m_AutoConnectInterval = 10;

        // Override ToString method to provide a custom string representation
        public override string ToString()
        {
            return String.Format("{0} {1}:{2}", this.GetType(), this.m_Server, this.m_Port);
        }

        // Private class for managing auto-connect locking
        private class Locker_AutoConnectClass
        {
        }
        private Locker_AutoConnectClass Locker_AutoConnect = new Locker_AutoConnectClass();

        // Delegates and events for various TCP client events
        public delegate void DelegateDataReceived(TCPServerVoice.TCPClient client, Byte[] bytes);
        public delegate void DelegateDataSend(TCPServerVoice.TCPClient client, Byte[] bytes);
        public delegate void DelegateDataReceivedComplete(TCPServerVoice.TCPClient client, String message);
        public delegate void DelegateConnection(TCPServerVoice.TCPClient client, string ITCPServerVoiceo);
        public delegate void DelegateException(TCPServerVoice.TCPClient client, Exception ex);
        public event DelegateDataReceived DataReceived;
        public event DelegateDataSend DataSend;
        public event DelegateConnection ClientConnected;
        public event DelegateConnection ClientDisconnected;
        public event DelegateException ExceptionAppeared;

        // Initialize the auto-connect timer
        private void InitTimerAutoConnect()
        {
            if (m_AutoConnect)
            {
                if (m_TimerAutoConnect == null)
                {
                    if (m_AutoConnectInterval > 0)
                    {
                        // Create and start the auto-connect timer
                        m_TimerAutoConnect = new System.Threading.Timer(new System.Threading.TimerCallback(OnTimer_AutoConnect), null, m_AutoConnectInterval * 1000, m_AutoConnectInterval * 1000);
                    }
                }
            }
        }

        // Send data over the TCP connection
        public void Send(Byte[] data)
        {
            try
            {
                m_NetStream.Write(data, 0, data.Length);

                if (this.DataSend != null)
                {
                    this.DataSend(this, data);
                }
            }
            catch (Exception ex)
            {
                ExceptionAppeared(this, ex);
            }
        }

        // Start reading data from the TCP connection
        private void StartReading()
        {
            try
            {
                m_ByteBuffer = new byte[1024];
                m_NetStream.BeginRead(m_ByteBuffer, 0, m_ByteBuffer.Length, new AsyncCallback(OnDataReceived), m_NetStream);
            }
            catch (Exception ex)
            {
                ExceptionAppeared(this, ex);
            }
        }

        // Callback for handling data received from the TCP connection
        private void OnDataReceived(IAsyncResult ar)
        {
            try
            {
                NetworkStream myNetworkStream = (NetworkStream)ar.AsyncState;

                if (myNetworkStream.CanRead)
                {
                    int numberOfBytesRead = myNetworkStream.EndRead(ar);

                    if (numberOfBytesRead > 0)
                    {
                        if (this.DataReceived != null)
                        {
                            Byte[] data = new byte[numberOfBytesRead];
                            System.Array.Copy(m_ByteBuffer, 0, data, 0, numberOfBytesRead);

                            this.DataReceived(this, data);
                        }
                    }
                    else
                    {
                        if (this.ClientDisconnected != null)
                        {
                            this.ClientDisconnected(this, "FIN");
                        }

                        if (m_AutoConnect == false)
                        {
                            this.disconnect_intern();
                        }
                        else
                        {
                            this.Disconnect_ButAutoConnect();
                        }

                        return;
                    }

                    myNetworkStream.BeginRead(m_ByteBuffer, 0, m_ByteBuffer.Length, new AsyncCallback(OnDataReceived), myNetworkStream);
                }
            }
            catch (Exception ex)
            {
                ExceptionAppeared(this, ex);
            }
        }

        // Reconnect to the server
        public void ReConnect()
        {
            this.Disconnect();
            this.Connect();
        }

        // Connect to the server
        public void Connect()
        {
            try
            {
                InitTimerAutoConnect();

                Client = new TcpClient(this.m_Server, this.m_Port);
                m_NetStream = Client.GetStream();

                this.StartReading();

                ClientConnected(this, String.Format("server: {0} port: {1}", this.m_Server, this.m_Port));
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        // Disconnect from the server
        public void Disconnect()
        {
            disconnect_intern();

            if (m_TimerAutoConnect != null)
            {
                m_TimerAutoConnect.Dispose();
                m_TimerAutoConnect = null;
            }

            if (this.ClientDisconnected != null)
            {
                this.ClientDisconnected(this, "Verbindung beendet");
            }
        }

        // Disconnect from the server without affecting auto-connect
        private void Disconnect_ButAutoConnect()
        {
            disconnect_intern();
        }

        // Internal method to handle disconnection
        private void disconnect_intern()
        {
            if (Client != null)
            {
                Client.Close();
            }
            if (m_NetStream != null)
            {
                m_NetStream.Close();
            }
        }

        // Timer callback for auto-reconnect
        private void OnTimer_AutoConnect(Object ob)
        {
            try
            {
                lock (Locker_AutoConnect)
                {
                    if (m_AutoConnect)
                    {
                        if (Client == null || Client.Connected == false)
                        {
                            Client = new TcpClient(this.m_Server, this.m_Port);
                            m_NetStream = Client.GetStream();

                            this.StartReading();

                            ClientConnected(this, String.Format("server: {0} port: {1}", this.m_Server, this.m_Port));
                        }
                    }
                    else
                    {
                        if (m_TimerAutoConnect != null)
                        {
                            m_TimerAutoConnect.Dispose();
                            m_TimerAutoConnect = null;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ExceptionAppeared(this, ex);
            }
        }

        // Event handler for exception occurrence
        private void OnExceptionAppeared(TCPServerVoice.TCPClient client, Exception ex)
        {

        }

        // Event handler for client connection
        private void OnConnected(TCPServerVoice.TCPClient client, string iTCPServerVoiceo)
        {

        }

        // Event handler for client disconnection
        private void OnDisconnected(TCPServerVoice.TCPClient client, string iTCPServerVoiceo)
        {

        }

        // Property to get or set the auto-connect interval
        public Int32 AutoConnectInterval
        {
            get
            {
                return m_AutoConnectInterval;
            }
            set
            {
                m_AutoConnectInterval = value;

                if (value > 0)
                {
                    try
                    {
                        if (m_TimerAutoConnect != null)
                        {
                            m_TimerAutoConnect.Change(value * 1000, value * 1000);
                        }
                    }
                    catch (Exception ex)
                    {
                        ExceptionAppeared(this, ex);
                    }
                }
            }
        }

        // Property to get or set the auto-connect status
        public bool AutoConnect
        {
            get
            {
                return m_AutoConnect;
            }
            set
            {
                m_AutoConnect = value;

                if (value == true)
                {
                    InitTimerAutoConnect();
                }

            }
        }

        // Property to check if the auto-connect timer is running
        public bool IsRunning
        {
            get
            {
                return m_TimerAutoConnect != null;
            }
        }

        // Property to check if the client is connected
        public bool Connected
        {
            get
            {
                if (this.Client != null)
                {
                    return this.Client.Connected;
                }
                else
                {
                    return false;
                }
            }
        }
    }
}
