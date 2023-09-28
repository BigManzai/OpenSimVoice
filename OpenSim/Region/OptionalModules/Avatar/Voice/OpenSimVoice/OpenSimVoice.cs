using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
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

namespace OpenSim.Region.OptionalModules.Avatar.Voice.TCPServerVoice
{
    [Extension(Path = "/OpenSim/RegionModules", NodeName = "RegionModule", Id = "TCPServerVoiceModule")]

    public class TCPServerVoiceModule : ISharedRegionModule, IVoiceModule
    {
        private static readonly ILog m_log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static bool   m_Enabled  = false;
        private static string m_tCPServerAPIPrefix;

        private static string m_tCPServerRealm;
        private static string m_tCPServerSIPProxy;
        private static bool m_tCPServerAttemptUseSTUN;
        private static string m_tCPServerEchoServer;
        private static int m_tCPServerEchoPort;
        private static string m_tCPServerDefaultWellKnownIP;
        private static int m_tCPServerDefaultTimeout;
        private static string m_tCPServerUrlResetPassword;
        private uint m_tCPServerServicePort;
        private string m_openSimWellKnownHTTPAddress;

        private readonly Dictionary<string, string> m_UUIDName = new Dictionary<string, string>();
        private Dictionary<string, string> m_ParcelAddress = new Dictionary<string, string>();

        private IConfig m_Config;

        private ITCPServerService m_TCPServerService;

        public void Initialise(IConfigSource config)
        {
            m_Config = config.Configs["TCPServerVoice"];

            if (m_Config == null)
                return;

            if (!m_Config.GetBoolean("Enabled", false))
                return;

            try
            {
                string serviceDll = m_Config.GetString("LocalServiceModule",
                        String.Empty);

                if (serviceDll.Length == 0)
                {
                    m_log.Error("[TCPServerVoice]: No LocalServiceModule named in section TCPServerVoice.  Not starting.");
                    return;
                }

                Object[] args = new Object[] { config };
                m_TCPServerService = ServerUtils.LoadPlugin<ITCPServerService>(serviceDll, args);

                string jsonConfig = m_TCPServerService.GetJsonConfig();

                OSDMap map = (OSDMap)OSDParser.DeserializeJson(jsonConfig);

                m_tCPServerAPIPrefix = map["APIPrefix"].AsString();
                m_tCPServerRealm = map["Realm"].AsString();
                m_tCPServerSIPProxy = map["SIPProxy"].AsString();
                m_tCPServerAttemptUseSTUN = map["AttemptUseSTUN"].AsBoolean();
                m_tCPServerEchoServer = map["EchoServer"].AsString();
                m_tCPServerEchoPort = map["EchoPort"].AsInteger();
                m_tCPServerDefaultWellKnownIP = map["DefaultWellKnownIP"].AsString();
                m_tCPServerDefaultTimeout = map["DefaultTimeout"].AsInteger();
                m_tCPServerUrlResetPassword = String.Empty;

                if (String.IsNullOrEmpty(m_tCPServerRealm) ||
                    String.IsNullOrEmpty(m_tCPServerAPIPrefix))
                {
                    m_log.Error("[TCPServerVoice]: TCPServer service mis-configured.  Not starting.");
                    return;
                }

                MainServer.Instance.AddHTTPHandler(String.Format("{0}/viv_get_prelogin.php", m_tCPServerAPIPrefix), TCPServerSLVoiceGetPreloginHTTPHandler);
                MainServer.Instance.AddHTTPHandler(String.Format("{0}/tcpserver-config", m_tCPServerAPIPrefix), TCPServerConfigHTTPHandler);
                MainServer.Instance.AddHTTPHandler(String.Format("{0}/viv_signin.php", m_tCPServerAPIPrefix), TCPServerSLVoiceSigninHTTPHandler);
                MainServer.Instance.AddHTTPHandler(String.Format("{0}/viv_buddy.php", m_tCPServerAPIPrefix), TCPServerSLVoiceBuddyHTTPHandler);
                MainServer.Instance.AddHTTPHandler(String.Format("{0}/viv_watcher.php", m_tCPServerAPIPrefix), TCPServerSLVoiceWatcherHTTPHandler);

                m_log.InfoFormat("[TCPServerVoice]: using TCPServer server {0}", m_tCPServerRealm);

                m_Enabled = true;

                m_log.Info("[TCPServerVoice]: plugin enabled");
            }
            catch (Exception e)
            {
                m_log.ErrorFormat("[TCPServerVoice]: plugin initialization failed: {0} {1}", e.Message, e.StackTrace);
                return;
            }
        }

        public void PostInitialise()
        {
        }

        public void AddRegion(Scene scene)
        {
            m_openSimWellKnownHTTPAddress = scene.RegionInfo.ExternalHostName;
            m_tCPServerServicePort = MainServer.Instance.Port;

            if (m_Enabled)
            {
                scene.EventManager.OnRegisterCaps += delegate(UUID agentID, Caps caps)
                    {
                        OnRegisterCaps(scene, agentID, caps);
                    };
            }
        }

        public void RemoveRegion(Scene scene)
        {
        }

        public void RegionLoaded(Scene scene)
        {
            if (m_Enabled)
            {
                m_log.Info("[TCPServerVoice]: registering IVoiceModule with the scene");

                scene.RegisterModuleInterface<IVoiceModule>(this);
            }
        }

        public void Close()
        {
        }

        public string Name
        {
            get { return "TCPServerVoiceModule"; }
        }

        public Type ReplaceableInterface
        {
            get { return null; }
        }

        public void setLandSIPAddress(string SIPAddress,UUID GlobalID)
        {
            m_log.DebugFormat("[TCPServerVoice]: setLandSIPAddress parcel id {0}: setting sip address {1}",
                                  GlobalID, SIPAddress);

            lock (m_ParcelAddress)
            {
                if (m_ParcelAddress.ContainsKey(GlobalID.ToString()))
                {
                    m_ParcelAddress[GlobalID.ToString()] = SIPAddress;
                }
                else
                {
                    m_ParcelAddress.Add(GlobalID.ToString(), SIPAddress);
                }
            }
        }

        public void OnRegisterCaps(Scene scene, UUID agentID, Caps caps)
        {
            m_log.DebugFormat(
                "[TCPServerVoice]: OnRegisterCaps() called with agentID {0} caps {1} in scene {2}",
                agentID, caps, scene.RegionInfo.RegionName);

            caps.RegisterSimpleHandler("ProvisionVoiceAccountRequest",
                    new SimpleStreamHandler("/" + UUID.Random(), delegate (IOSHttpRequest httpRequest, IOSHttpResponse httpResponse)
                    {
                        ProvisionVoiceAccountRequest(httpRequest, httpResponse, agentID, scene);
                    }));

            caps.RegisterSimpleHandler("ParcelVoiceInfoRequest",
                    new SimpleStreamHandler("/" + UUID.Random(), delegate (IOSHttpRequest httpRequest, IOSHttpResponse httpResponse)
                    {
                        ParcelVoiceInfoRequest(httpRequest, httpResponse, agentID, scene);
                    }));
        }

        public void ProvisionVoiceAccountRequest(IOSHttpRequest request, IOSHttpResponse response, UUID agentID, Scene scene)
        {
            if(request.HttpMethod != "POST")
            {
                response.StatusCode = (int)HttpStatusCode.NotFound;
                return;
            }

            m_log.DebugFormat(
                "[TCPServerVoice][PROVISIONVOICE]: ProvisionVoiceAccountRequest() request for {0}", agentID.ToString());

            response.StatusCode = (int)HttpStatusCode.OK;

            ScenePresence avatar = scene.GetScenePresence(agentID);
            if (avatar == null)
            {
                System.Threading.Thread.Sleep(2000);
                avatar = scene.GetScenePresence(agentID);

                if (avatar == null)
                {
                    response.RawBuffer = Util.UTF8.GetBytes("<llsd>undef</llsd>");
                    return;
                }
            }
            string avatarName = avatar.Name;

            try
            {
                string agentname = "x" + Convert.ToBase64String(agentID.GetBytes());
                string password  = "1234";

                agentname = agentname.Replace('+', '-').Replace('/', '_');

                lock (m_UUIDName)
                {
                    if (m_UUIDName.ContainsKey(agentname))
                    {
                        m_UUIDName[agentname] = avatarName;
                    }
                    else
                    {
                        m_UUIDName.Add(agentname, avatarName);
                    }
                }

                string accounturl = String.Format("http://{0}:{1}{2}/", m_openSimWellKnownHTTPAddress,
                                                              m_tCPServerServicePort, m_tCPServerAPIPrefix);
                osUTF8 lsl = LLSDxmlEncode2.Start();
                LLSDxmlEncode2.AddMap(lsl);
                LLSDxmlEncode2.AddElem("username", agentname, lsl);
                LLSDxmlEncode2.AddElem("password", password, lsl);
                LLSDxmlEncode2.AddElem("voice_sip_uri_hostname", m_tCPServerRealm, lsl);
                LLSDxmlEncode2.AddElem("voice_account_server_name", accounturl, lsl);
                LLSDxmlEncode2.AddEndMap(lsl);
                response.RawBuffer = LLSDxmlEncode2.EndToBytes(lsl);
            }
            catch (Exception e)
            {
                m_log.ErrorFormat("[TCPServerVoice][PROVISIONVOICE]: avatar \"{0}\": {1}, retry later", avatarName, e.Message);
                m_log.DebugFormat("[TCPServerVoice][PROVISIONVOICE]: avatar \"{0}\": {1} failed", avatarName, e.ToString());

                response.RawBuffer = osUTF8.GetASCIIBytes("<llsd>undef</llsd>");
            }
        }
        public void ParcelVoiceInfoRequest(IOSHttpRequest request, IOSHttpResponse response, UUID agentID, Scene scene)
        {
            if (request.HttpMethod != "POST")
            {
                response.StatusCode = (int)HttpStatusCode.NotFound;
                return;
            }

            response.StatusCode = (int)HttpStatusCode.OK;

            m_log.DebugFormat(
                "[TCPServerVoice][PARCELVOICE]: ParcelVoiceInfoRequest() on {0} for {1}",
                scene.RegionInfo.RegionName, agentID);

            ScenePresence avatar = scene.GetScenePresence(agentID);
            if(avatar == null)
            {
                response.RawBuffer = Util.UTF8.GetBytes("<llsd>undef</llsd>");
                return;
            }

            string avatarName = avatar.Name;

            try
            {
                string channelUri;

                if (null == scene.LandChannel)
                {
                    m_log.ErrorFormat("region \"{0}\": avatar \"{1}\": land data not yet available", scene.RegionInfo.RegionName, avatarName);
                    response.RawBuffer = Util.UTF8.GetBytes("<llsd>undef</llsd>");
                    return;
                }

                LandData land = scene.GetLandData(avatar.AbsolutePosition);

                 if (!scene.RegionInfo.EstateSettings.AllowVoice)
                 {
                     m_log.DebugFormat("[TCPServerVoice][PARCELVOICE]: region \"{0}\": voice not enabled in estate settings", scene.RegionInfo.RegionName);
                    channelUri = String.Empty;
                }
                else

                if (!scene.RegionInfo.EstateSettings.TaxFree && (land.Flags & (uint)ParcelFlags.AllowVoiceChat) == 0)
                {
                    channelUri = String.Empty;
                }
                else
                {
                    channelUri = ChannelUri(scene, land);
                }

                osUTF8 lsl = LLSDxmlEncode2.Start(512);
                LLSDxmlEncode2.AddMap(lsl);
                LLSDxmlEncode2.AddElem("parcel_local_id", land.LocalID, lsl);
                LLSDxmlEncode2.AddElem("region_name", scene.Name, lsl);
                LLSDxmlEncode2.AddMap("voice_credentials", lsl);
                LLSDxmlEncode2.AddElem("channel_uri", channelUri, lsl);
                LLSDxmlEncode2.AddEndMap(lsl);
                LLSDxmlEncode2.AddEndMap(lsl);

                response.RawBuffer= LLSDxmlEncode2.EndToBytes(lsl);
            }
            catch (Exception e)
            {
                m_log.ErrorFormat("[TCPServerVoice][PARCELVOICE]: region \"{0}\": avatar \"{1}\": {2}, retry later", scene.RegionInfo.RegionName, avatarName, e.Message);
                m_log.DebugFormat("[TCPServerVoice][PARCELVOICE]: region \"{0}\": avatar \"{1}\": {2} failed", scene.RegionInfo.RegionName, avatarName, e.ToString());

                response.RawBuffer = Util.UTF8.GetBytes("<llsd>undef</llsd>");
            }
        }

        public string ChatSessionRequest(Scene scene, string request, string path, string param, UUID agentID, Caps caps)
        {
            ScenePresence avatar = scene.GetScenePresence(agentID);
            string        avatarName = avatar.Name;

            m_log.DebugFormat("[TCPServerVoice][CHATSESSION]: avatar \"{0}\": request: {1}, path: {2}, param: {3}", avatarName, request, path, param);

            return "<llsd>true</llsd>";
        }

        public Hashtable ForwardProxyRequest(Hashtable request)
        {
            m_log.Debug("[PROXYING]: -------------------------------proxying request");
            Hashtable response = new Hashtable();
            response["content_type"] = "text/xml";
            response["str_response_string"] = "";
            response["int_response_code"] = 200;

            string forwardaddress = "https://www.bhr.vivox.com/api2/";
            string body = (string)request["body"];
            string method = (string) request["http-method"];
            string contenttype = (string) request["content-type"];
            string uri = (string) request["uri"];
            uri = uri.Replace("/api/", "");
            forwardaddress += uri;


            string fwdresponsestr = "";
            int fwdresponsecode = 200;
            string fwdresponsecontenttype = "text/xml";

            HttpWebRequest forwardreq = (HttpWebRequest)WebRequest.Create(forwardaddress);
            forwardreq.Method = method;
            forwardreq.ContentType = contenttype;
            forwardreq.KeepAlive = false;
            forwardreq.ServerCertificateValidationCallback = CustomCertificateValidation;

            if (method == "POST")
            {
                byte[] contentreq = Util.UTF8.GetBytes(body);
                forwardreq.ContentLength = contentreq.Length;
                Stream reqStream = forwardreq.GetRequestStream();
                reqStream.Write(contentreq, 0, contentreq.Length);
                reqStream.Close();
            }

            using (HttpWebResponse fwdrsp = (HttpWebResponse)forwardreq.GetResponse())
            {
                Encoding encoding = Util.UTF8;

                using (Stream s = fwdrsp.GetResponseStream())
                {
                    using (StreamReader fwdresponsestream = new StreamReader(s))
                    {
                        fwdresponsestr = fwdresponsestream.ReadToEnd();
                        fwdresponsecontenttype = fwdrsp.ContentType;
                        fwdresponsecode = (int)fwdrsp.StatusCode;
                    }
                }
            }

            response["content_type"] = fwdresponsecontenttype;
            response["str_response_string"] = fwdresponsestr;
            response["int_response_code"] = fwdresponsecode;

            return response;
        }

        public Hashtable TCPServerSLVoiceGetPreloginHTTPHandler(Hashtable request)
        {
            Hashtable response = new Hashtable();
            response["content_type"] = "text/xml";
            response["keepalive"] = false;

            response["str_response_string"] = String.Format(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" +
                "<VCConfiguration>\r\n"+
                    "<DefaultRealm>{0}</DefaultRealm>\r\n" +
                    "<DefaultSIPProxy>{1}</DefaultSIPProxy>\r\n"+
                    "<DefaultAttemptUseSTUN>{2}</DefaultAttemptUseSTUN>\r\n"+
                    "<DefaultEchoServer>{3}</DefaultEchoServer>\r\n"+
                    "<DefaultEchoPort>{4}</DefaultEchoPort>\r\n"+
                    "<DefaultWellKnownIP>{5}</DefaultWellKnownIP>\r\n"+
                    "<DefaultTimeout>{6}</DefaultTimeout>\r\n"+
                    "<UrlResetPassword>{7}</UrlResetPassword>\r\n"+
                    "<UrlPrivacyNotice>{8}</UrlPrivacyNotice>\r\n"+
                    "<UrlEulaNotice/>\r\n"+
                    "<App.NoBottomLogo>false</App.NoBottomLogo>\r\n"+
                "</VCConfiguration>",
                m_tCPServerRealm, m_tCPServerSIPProxy, m_tCPServerAttemptUseSTUN,
                m_tCPServerEchoServer, m_tCPServerEchoPort,
                m_tCPServerDefaultWellKnownIP, m_tCPServerDefaultTimeout,
                m_tCPServerUrlResetPassword, "");

            response["int_response_code"] = 200;

            return response;
        }

        public Hashtable TCPServerSLVoiceBuddyHTTPHandler(Hashtable request)
        {
            m_log.Debug("[TCPServerVoice]: TCPServerSLVoiceBuddyHTTPHandler called");

            Hashtable response = new Hashtable();
            response["int_response_code"] = 200;
            response["str_response_string"] = string.Empty;
            response["content-type"] = "text/xml";

            Hashtable requestBody = ParseRequestBody((string)request["body"]);

            if (!requestBody.ContainsKey("auth_token"))
                return response;

            string auth_token = (string)requestBody["auth_token"];
            int strcount = 0;

            string[] ids = new string[strcount];

            int iter = -1;
            lock (m_UUIDName)
            {
                strcount = m_UUIDName.Count;
                ids = new string[strcount];
                foreach (string s in m_UUIDName.Keys)
                {
                    iter++;
                    ids[iter] = s;
                }
            }
            StringBuilder resp = new StringBuilder();
            resp.Append("<?xml version=\"1.0\" encoding=\"iso-8859-1\" ?><response xmlns=\"http://www.vivox.com\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation= \"/xsd/buddy_list.xsd\">");

            resp.Append(string.Format(@"<level0>
                        <status>OK</status>
                        <cookie_name>lib_session</cookie_name>
                        <cookie>{0}</cookie>
                        <auth_token>{0}</auth_token>
                        <body>
                            <buddies>",auth_token));
            for (int i=0;i<ids.Length;i++)
            {
                DateTime currenttime = DateTime.Now;
                string dt = currenttime.ToString("yyyy-MM-dd HH:mm:ss.0zz");
                resp.Append(
                    string.Format(@"<level3>
                                    <bdy_id>{1}</bdy_id>
                                    <bdy_data></bdy_data>
                                    <bdy_uri>sip:{0}@{2}</bdy_uri>
                                    <bdy_nickname>{0}</bdy_nickname>
                                    <bdy_username>{0}</bdy_username>
                                    <bdy_domain>{2}</bdy_domain>
                                    <bdy_status>A</bdy_status>
                                    <modified_ts>{3}</modified_ts>
                                    <b2g_group_id></b2g_group_id>
                                </level3>", ids[i], i ,m_tCPServerRealm, dt));
            }

            resp.Append("</buddies><groups></groups></body></level0></response>");

            response["str_response_string"] = resp.ToString();
            return response;
        }

        public Hashtable TCPServerSLVoiceWatcherHTTPHandler(Hashtable request)
        {
            m_log.Debug("[TCPServerVoice]: TCPServerSLVoiceWatcherHTTPHandler called");

            Hashtable response = new Hashtable();
            response["int_response_code"] = 200;
            response["content-type"] = "text/xml";

            Hashtable requestBody = ParseRequestBody((string)request["body"]);

            string auth_token = (string)requestBody["auth_token"];

            StringBuilder resp = new StringBuilder();
            resp.Append("<?xml version=\"1.0\" encoding=\"iso-8859-1\" ?><response xmlns=\"http://www.vivox.com\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation= \"/xsd/buddy_list.xsd\">");

            resp.Append(string.Format(@"<level0>
                        <status>OK</status>
                        <cookie_name>lib_session</cookie_name>
                        <cookie>{0}</cookie>
                        <auth_token>{0}</auth_token>
                        <body/></level0></response>", auth_token));

            response["str_response_string"] = resp.ToString();

            return response;
        }

        public Hashtable TCPServerSLVoiceSigninHTTPHandler(Hashtable request)
        {

            Hashtable requestBody = ParseRequestBody((string)request["body"]);

            string userid = (string) requestBody["userid"];

            string avatarName = string.Empty;
            int pos = -1;
            lock (m_UUIDName)
            {
                if (m_UUIDName.ContainsKey(userid))
                {
                    avatarName = m_UUIDName[userid];
                    foreach (string s in m_UUIDName.Keys)
                    {
                        pos++;
                        if (s == userid)
                            break;
                    }
                }
            }

            Hashtable response = new Hashtable();
            response["str_response_string"] = string.Format(@"<response xsi:schemaLocation=""/xsd/signin.xsd"">
                    <level0>
                        <status>OK</status>
                        <body>
                        <code>200</code>
                        <cookie_name>lib_session</cookie_name>
                        <cookie>{0}:{1}:9303959503950::</cookie>
                        <auth_token>{0}:{1}:9303959503950::</auth_token>
                        <primary>1</primary>
                        <account_id>{1}</account_id>
                        <displayname>{2}</displayname>
                        <msg>auth successful</msg>
                        </body>
                    </level0>
                </response>", userid, pos, avatarName);

            response["int_response_code"] = 200;

            return response;
        }

        public Hashtable ParseRequestBody(string body)
        {
            Hashtable bodyParams = new Hashtable();
            string [] nvps = body.Split(new Char [] {'&'});

            foreach (string s in nvps)
            {
                if (s.Trim() != "")
                {
                    string [] nvp = s.Split(new Char [] {'='});
                    bodyParams.Add(HttpUtility.UrlDecode(nvp[0]), HttpUtility.UrlDecode(nvp[1]));
                }
            }

            return bodyParams;
        }

        private string ChannelUri(Scene scene, LandData land)
        {
            string channelUri = null;

            string landUUID;
            string landName;

            lock (m_ParcelAddress)
            {
                if (m_ParcelAddress.ContainsKey(land.GlobalID.ToString()))
                {
                    m_log.DebugFormat("[TCPServerVoice]: parcel id {0}: using sip address {1}", land.GlobalID, m_ParcelAddress[land.GlobalID.ToString()]);
                    return m_ParcelAddress[land.GlobalID.ToString()];
                }
            }

            if (land.LocalID != 1 && (land.Flags & (uint)ParcelFlags.UseEstateVoiceChan) == 0)
            {
                landName = String.Format("{0}:{1}", scene.RegionInfo.RegionName, land.Name);
                landUUID = land.GlobalID.ToString();
                m_log.DebugFormat("[TCPServerVoice]: Region:Parcel \"{0}\": parcel id {1}: using channel name {2}", landName, land.LocalID, landUUID);
            }
            else
            {
                landName = String.Format("{0}:{1}", scene.RegionInfo.RegionName, scene.RegionInfo.RegionName);
                landUUID = scene.RegionInfo.RegionID.ToString();
                m_log.DebugFormat("[TCPServerVoice]: Region:Parcel \"{0}\": parcel id {1}: using channel name {2}", landName, land.LocalID, landUUID);
            }

            channelUri = String.Format("sip:conf-{0}@{1}", "x" + Convert.ToBase64String(Encoding.ASCII.GetBytes(landUUID)), m_tCPServerRealm);

            lock (m_ParcelAddress)
            {
                if (!m_ParcelAddress.ContainsKey(land.GlobalID.ToString()))
                {
                    m_ParcelAddress.Add(land.GlobalID.ToString(),channelUri);
                }
            }

            return channelUri;
        }

        private static bool CustomCertificateValidation(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors error)
        {
            return true;
        }

        public Hashtable TCPServerConfigHTTPHandler(Hashtable request)
        {
            Hashtable response = new Hashtable();
            response["str_response_string"] = string.Empty;
            response["content_type"] = "text/plain";
            response["keepalive"] = false;
            response["int_response_code"] = 500;

            Hashtable requestBody = ParseRequestBody((string)request["body"]);

            string section = (string) requestBody["section"];

            if (section == "directory")
            {
                string eventCallingFunction = (string)requestBody["Event-Calling-Function"];
                m_log.DebugFormat("[TCPServerVoice]: Received request for config section directory, event calling function '{0}'", eventCallingFunction);

                response = m_TCPServerService.HandleDirectoryRequest(requestBody);
            }
            else if (section == "dialplan")
            {
                m_log.DebugFormat("[TCPServerVoice]: Received request for config section dialplan");

                response = m_TCPServerService.HandleDialplanRequest(requestBody);
            }
            else
                m_log.WarnFormat("[TCPServerVoice]: Unknown section {0} was requested from config.", section);

            return response;
        }
    }

    internal class ITCPServerService
    {
        internal string GetJsonConfig()
        {
            throw new NotImplementedException();
        }

        internal Hashtable HandleDialplanRequest(Hashtable requestBody)
        {
            throw new NotImplementedException();
        }

        internal Hashtable HandleDirectoryRequest(Hashtable requestBody)
        {
            throw new NotImplementedException();
        }
    }

    public class TCPServer : ISharedRegionModule, IVoiceModule
    {        
        public TCPServer()
        {

        }

        private IPEndPoint m_endpoint;
        private TcpListener m_tcpip;
        private Thread m_ThreadMainServer;
        private ListenerState m_State;

        private List<ServerThread> m_threads = new List<ServerThread>();

        public delegate void DelegateClientConnected(ServerThread st);
        public delegate void DelegateClientDisconnected(ServerThread st, string info);
        public delegate void DelegateDataReceived(ServerThread st, Byte[] data);

        public event DelegateClientConnected ClientConnected;
        public event DelegateClientDisconnected ClientDisconnected;
        public event DelegateDataReceived DataReceived;

        public enum ListenerState
        {
            None,
            Started,
            Stopped,
            Error
        };

        public List<ServerThread> Clients
        {
            get
            {
                return m_threads;
            }
        }

        public ListenerState State
        {
            get
            {
                return m_State;
            }
        }

        public TcpListener Listener
        {
            get
            {
                return this.m_tcpip;
            }
        }

        string IRegionModuleBase.Name => throw new NotImplementedException();

        Type IRegionModuleBase.ReplaceableInterface => throw new NotImplementedException();

        public void Start(string strIPAdress, int Port)
        {
            m_endpoint = new IPEndPoint(IPAddress.Parse(strIPAdress), Port);
            m_tcpip = new TcpListener(m_endpoint);

            if (m_tcpip == null) return;

            try
            {
                m_tcpip.Start();

                m_ThreadMainServer = new Thread(new ThreadStart(Run));
                m_ThreadMainServer.Start();

                this.m_State = ListenerState.Started;
            }
            catch (Exception ex)
            {
                m_tcpip.Stop();
                this.m_State = ListenerState.Error;

                throw ex;
            }
        }

        private void Run()
        {
            while (true)
            {
                TcpClient client = m_tcpip.AcceptTcpClient();
                ServerThread st = new ServerThread(client);

                st.DataReceived += new ServerThread.DelegateDataReceived(OnDataReceived);
                st.ClientDisconnected += new ServerThread.DelegateClientDisconnected(OnClientDisconnected);

                OnClientConnected(st);

                try
                {
                    client.Client.BeginReceive(st.ReadBuffer, 0, st.ReadBuffer.Length, SocketFlags.None, st.Receive, client.Client);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
        }

        public int Send(Byte[] data)
        {
					  List<ServerThread> list = new List<ServerThread>(m_threads);
            foreach (ServerThread sv in list)
            {
                try
                {
                    if (data.Length > 0)
                    {
                        sv.Send(data);
                    }
                }
                catch (Exception)
                {

                }
            }
            return m_threads.Count;
        }

        private void OnDataReceived(ServerThread st, Byte[] data)
        {
            if (DataReceived != null)
            {
                DataReceived(st, data);
            }
        }

        private void OnClientDisconnected(ServerThread st, string info)
        {
            m_threads.Remove(st);

            if (ClientDisconnected != null)
            {
                ClientDisconnected(st, info);
            }
        }

        private void OnClientConnected(ServerThread st)
        {
            if (!m_threads.Contains(st))
            {
                m_threads.Add(st);
            }

            if (ClientConnected != null)
            {
                ClientConnected(st);
            }
        }
        public void Stop()
        {
            try
            {
                if (m_ThreadMainServer != null)
                {
                    m_ThreadMainServer.Abort();
                    System.Threading.Thread.Sleep(100);
                }

                for (IEnumerator en = m_threads.GetEnumerator(); en.MoveNext(); )
                {
                    ServerThread st = (ServerThread)en.Current;
                    st.Stop();

                    if (ClientDisconnected != null)
                    {
                        ClientDisconnected(st, "Connection has been terminated");
                    }
                }

                if (m_tcpip != null)
                {
                    m_tcpip.Stop();
                    m_tcpip.Server.Close();
                }

                m_threads.Clear();
                this.m_State = ListenerState.Stopped;

            }
            catch (Exception)
            {
                this.m_State = ListenerState.Error;
            }
        }

        void ISharedRegionModule.PostInitialise()
        {
            throw new NotImplementedException();
        }

        void IRegionModuleBase.Initialise(IConfigSource source)
        {
            throw new NotImplementedException();
        }

        void IRegionModuleBase.Close()
        {
            throw new NotImplementedException();
        }

        void IRegionModuleBase.AddRegion(Scene scene)
        {
            throw new NotImplementedException();
        }

        void IRegionModuleBase.RemoveRegion(Scene scene)
        {
            throw new NotImplementedException();
        }

        void IRegionModuleBase.RegionLoaded(Scene scene)
        {
            throw new NotImplementedException();
        }

        void IVoiceModule.setLandSIPAddress(string SIPAddress, UUID GlobalID)
        {
            throw new NotImplementedException();
        }
    }

    public class ServerThread
    {
        private bool m_IsStopped = false;
        private TcpClient m_Connection = null;
        public byte[] ReadBuffer = new byte[1024];
        public bool IsMute = false;
        public String Name = "";

        public delegate void DelegateDataReceived(ServerThread st, Byte[] data);
        public event DelegateDataReceived DataReceived;
        public delegate void DelegateClientDisconnected(ServerThread sv, string info);
        public event DelegateClientDisconnected ClientDisconnected;

        public TcpClient Client
        {
            get
            {
                return m_Connection;
            }
        }
        public bool IsStopped
        {
            get
            {
                return m_IsStopped;
            }
        }
        public ServerThread(TcpClient connection)
        {
            this.m_Connection = connection;
        }
        public void Receive(IAsyncResult ar)
        {
            try
            {
                if (this.m_Connection.Client.Connected == false)
                {
                    return;
                }

                if (ar.IsCompleted)
                {
                    int bytesRead = m_Connection.Client.EndReceive(ar);

                    if (bytesRead > 0)
                    {
                        Byte[] data = new byte[bytesRead];
                        System.Array.Copy(ReadBuffer, 0, data, 0, bytesRead);

                        DataReceived(this, data);
                        m_Connection.Client.BeginReceive(ReadBuffer, 0, ReadBuffer.Length, SocketFlags.None, Receive, m_Connection.Client);
                    }
                    else
                    {
                        HandleDisconnection("Connection has been terminated");
                    }
                }
            }
            catch (Exception ex)
            {
                HandleDisconnection(ex.Message);
            }
        }

        public void HandleDisconnection(string reason)
        {
            m_IsStopped = true;

            if (ClientDisconnected != null)
            {
                ClientDisconnected(this, reason);
            }
        }

        public void Send(Byte[] data)
        {
            try
            {
                if (this.m_IsStopped == false)
                {
                    NetworkStream ns = this.m_Connection.GetStream();

                    lock (ns)
                    {
                        ns.Write(data, 0, data.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                this.m_Connection.Close();
                this.m_IsStopped = true;

                if (ClientDisconnected != null)
                {
                    ClientDisconnected(this, ex.Message);
                }

                throw ex;
            }
        }
        public void Stop()
        {
            if (m_Connection.Client.Connected == true)
            {
                m_Connection.Client.Disconnect(false);
            }

            this.m_IsStopped = true;
        }
    }
}
