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
            // Assign the "TCPServerVoice" configuration section to m_Config
            m_Config = config.Configs["TCPServerVoice"];

            // If the configuration section is missing or "Enabled" is false, return early
            if (m_Config == null || !m_Config.GetBoolean("Enabled", false))
                return;

            try
            {
                // Get the service DLL path from the configuration
                string serviceDll = m_Config.GetString("LocalServiceModule", String.Empty);

                // If the DLL path is empty, log an error and return
                if (serviceDll.Length == 0)
                {
                    m_log.Error("[TCPServerVoice]: No LocalServiceModule named in section TCPServerVoice.  Not starting.");
                    return;
                }

                // Load a plugin using the DLL path and configuration arguments
                Object[] args = new Object[] { config };
                m_TCPServerService = ServerUtils.LoadPlugin<ITCPServerService>(serviceDll, args);

                // Deserialize JSON configuration and extract values
                string jsonConfig = m_TCPServerService.GetJsonConfig();
                OSDMap map = (OSDMap)OSDParser.DeserializeJson(jsonConfig);

                // Extract configuration values
                m_tCPServerAPIPrefix = map["APIPrefix"].AsString();
                m_tCPServerRealm = map["Realm"].AsString();
                // (other configuration values)

                // Check for essential configuration settings
                if (String.IsNullOrEmpty(m_tCPServerRealm) || String.IsNullOrEmpty(m_tCPServerAPIPrefix))
                {
                    m_log.Error("[TCPServerVoice]: TCPServer service mis-configured.  Not starting.");
                    return;
                }

                // Register HTTP handlers based on API prefix
                MainServer.Instance.AddHTTPHandler(String.Format("{0}/viv_get_prelogin.php", m_tCPServerAPIPrefix), TCPServerSLVoiceGetPreloginHTTPHandler);
                // (other handlers)

                // Enable the plugin and log success
                m_Enabled = true;
                m_log.Info("[TCPServerVoice]: plugin enabled");
            }
            catch (Exception e)
            {
                // Log error if any exceptions occur during initialization
                m_log.ErrorFormat("[TCPServerVoice]: plugin initialization failed: {0} {1}", e.Message, e.StackTrace);
                return;
            }
        }


        public void PostInitialise()
        {
            // This method is a placeholder for any post-initialization tasks.
            // Currently, it doesn't contain any code.
        }

        public void AddRegion(Scene scene)
        {
            // This method is called when a new region (or scene) is added.

            // Assign the external hostname of the scene to m_openSimWellKnownHTTPAddress.
            m_openSimWellKnownHTTPAddress = scene.RegionInfo.ExternalHostName;

            // Assign the port of the main server instance to m_tCPServerServicePort.
            m_tCPServerServicePort = MainServer.Instance.Port;

            // Check if the module is enabled.
            if (m_Enabled)
            {
                // Subscribe to the OnRegisterCaps event of the scene's event manager
                // and register the OnRegisterCaps method to handle this event.
                scene.EventManager.OnRegisterCaps += delegate (UUID agentID, Caps caps)
                {
                    OnRegisterCaps(scene, agentID, caps);
                };
            }
        }

        public void RemoveRegion(Scene scene)
        {
            // This method is called when a region (or scene) is removed.
            // Currently, it doesn't contain any code and is effectively a placeholder.
        }

        public void RegionLoaded(Scene scene)
        {
            // This method is called when a region (or scene) is loaded.

            // Check if the module is enabled.
            if (m_Enabled)
            {
                // Log an informational message indicating that the IVoiceModule is being registered with the scene.
                m_log.Info("[TCPServerVoice]: registering IVoiceModule with the scene");

                // Register the current object (this) as an implementation of the IVoiceModule interface with the scene.
                scene.RegisterModuleInterface<IVoiceModule>(this);
            }
        }

        public void Close()
        {
            // This method is likely intended to perform any necessary cleanup or finalization tasks
            // when the voice module is being closed or deactivated.
            // Currently, it doesn't contain any code.
        }


        public string Name
        {
            // This property defines the name of the TCPServerVoiceModule.
            get { return "TCPServerVoiceModule"; }
        }

        public Type ReplaceableInterface
        {
            // This property defines the replaceable interface, but it returns null.
            // It means that there is no specific interface that this module replaces.
            get { return null; }
        }

        public void setLandSIPAddress(string SIPAddress, UUID GlobalID)
        {
            // This method is used to set the SIP (Session Initiation Protocol) address for a land parcel.

            // Log a debug message indicating that the SIP address is being set for a parcel.
            m_log.DebugFormat("[TCPServerVoice]: setLandSIPAddress parcel id {0}: setting sip address {1}", GlobalID, SIPAddress);

            // Lock the access to the m_ParcelAddress dictionary to ensure thread safety.
            lock (m_ParcelAddress)
            {
                // Check if the dictionary already contains the GlobalID as a key.
                if (m_ParcelAddress.ContainsKey(GlobalID.ToString()))
                {
                    // If it does, update the SIP address for the existing key.
                    m_ParcelAddress[GlobalID.ToString()] = SIPAddress;
                }
                else
                {
                    // If it doesn't, add a new key-value pair for the GlobalID and SIPAddress.
                    m_ParcelAddress.Add(GlobalID.ToString(), SIPAddress);
                }
            }
        }

        public void OnRegisterCaps(Scene scene, UUID agentID, Caps caps)
        {
            // This method is called when registering capabilities (caps) for a specific agent in a scene.

            // Log a debug message with information about the agent, caps, and scene.
            m_log.DebugFormat("[TCPServerVoice]: OnRegisterCaps() called with agentID {0} caps {1} in scene {2}",
                              agentID, caps, scene.RegionInfo.RegionName);

            // Register a SimpleStreamHandler for handling "ProvisionVoiceAccountRequest" caps.
            caps.RegisterSimpleHandler("ProvisionVoiceAccountRequest",
                new SimpleStreamHandler("/" + UUID.Random(), delegate (IOSHttpRequest httpRequest, IOSHttpResponse httpResponse)
                {
                    ProvisionVoiceAccountRequest(httpRequest, httpResponse, agentID, scene);
                }));

            // Register a SimpleStreamHandler for handling "ParcelVoiceInfoRequest" caps.
            caps.RegisterSimpleHandler("ParcelVoiceInfoRequest",
                new SimpleStreamHandler("/" + UUID.Random(), delegate (IOSHttpRequest httpRequest, IOSHttpResponse httpResponse)
                {
                    ParcelVoiceInfoRequest(httpRequest, httpResponse, agentID, scene);
                }));
        }


        public void ProvisionVoiceAccountRequest(IOSHttpRequest request, IOSHttpResponse response, UUID agentID, Scene scene)
        {
            // Check if the HTTP request method is not POST
            if (request.HttpMethod != "POST")
            {
                // Set response status code to NotFound and return
                response.StatusCode = (int)HttpStatusCode.NotFound;
                return;
            }

            // Log a debug message with the agent ID
            m_log.DebugFormat("[TCPServerVoice][PROVISIONVOICE]: ProvisionVoiceAccountRequest() request for {0}", agentID.ToString());

            // Set response status code to OK
            response.StatusCode = (int)HttpStatusCode.OK;

            // Get the avatar (scene presence) by agent ID
            ScenePresence avatar = scene.GetScenePresence(agentID);

            // If the avatar is not found, wait for 2 seconds and try again
            if (avatar == null)
            {
                System.Threading.Thread.Sleep(2000);
                avatar = scene.GetScenePresence(agentID);

                // If still not found, set response with an undefined LLSD and return
                if (avatar == null)
                {
                    response.RawBuffer = Util.UTF8.GetBytes("<llsd>undef</llsd>");
                    return;
                }
            }
            string avatarName = avatar.Name;

            try
            {
                // Generate agent name and password for voice account
                string agentname = "x" + Convert.ToBase64String(agentID.GetBytes());
                string password = "1234";

                // Replace characters in agent name for URL safety
                agentname = agentname.Replace('+', '-').Replace('/', '_');

                // Lock to prevent concurrent access to m_UUIDName dictionary
                lock (m_UUIDName)
                {
                    // Update or add agentname to the m_UUIDName dictionary
                    if (m_UUIDName.ContainsKey(agentname))
                    {
                        m_UUIDName[agentname] = avatarName;
                    }
                    else
                    {
                        m_UUIDName.Add(agentname, avatarName);
                    }
                }

                // Create the account URL
                string accounturl = String.Format("http://{0}:{1}{2}/", m_openSimWellKnownHTTPAddress,
                                                              m_tCPServerServicePort, m_tCPServerAPIPrefix);

                // Encode data as LLSD XML
                osUTF8 lsl = LLSDxmlEncode2.Start();
                LLSDxmlEncode2.AddMap(lsl);
                LLSDxmlEncode2.AddElem("username", agentname, lsl);
                LLSDxmlEncode2.AddElem("password", password, lsl);
                LLSDxmlEncode2.AddElem("voice_sip_uri_hostname", m_tCPServerRealm, lsl);
                LLSDxmlEncode2.AddElem("voice_account_server_name", accounturl, lsl);
                LLSDxmlEncode2.AddEndMap(lsl);

                // Set the response buffer with the encoded LLSD XML data
                response.RawBuffer = LLSDxmlEncode2.EndToBytes(lsl);
            }
            catch (Exception e)
            {
                // Log an error message and set response with an undefined LLSD in case of an exception
                m_log.ErrorFormat("[TCPServerVoice][PROVISIONVOICE]: avatar \"{0}\": {1}, retry later", avatarName, e.Message);
                m_log.DebugFormat("[TCPServerVoice][PROVISIONVOICE]: avatar \"{0}\": {1} failed", avatarName, e.ToString());

                response.RawBuffer = osUTF8.GetASCIIBytes("<llsd>undef</llsd>");
            }
        }


        public void ParcelVoiceInfoRequest(IOSHttpRequest request, IOSHttpResponse response, UUID agentID, Scene scene)
        {
            // Check if the HTTP request method is not POST
            if (request.HttpMethod != "POST")
            {
                // Set response status code to NotFound and return
                response.StatusCode = (int)HttpStatusCode.NotFound;
                return;
            }

            // Set response status code to OK
            response.StatusCode = (int)HttpStatusCode.OK;

            // Log a debug message with the scene name and agent ID
            m_log.DebugFormat("[TCPServerVoice][PARCELVOICE]: ParcelVoiceInfoRequest() on {0} for {1}",
                scene.RegionInfo.RegionName, agentID);

            // Get the avatar (scene presence) by agent ID
            ScenePresence avatar = scene.GetScenePresence(agentID);

            // If the avatar is not found, set response with an undefined LLSD and return
            if (avatar == null)
            {
                response.RawBuffer = Util.UTF8.GetBytes("<llsd>undef</llsd>");
                return;
            }

            string avatarName = avatar.Name;

            try
            {
                string channelUri;

                // Check if the land channel is available
                if (null == scene.LandChannel)
                {
                    // Log an error message and set response with an undefined LLSD
                    m_log.ErrorFormat("region \"{0}\": avatar \"{1}\": land data not yet available", scene.RegionInfo.RegionName, avatarName);
                    response.RawBuffer = Util.UTF8.GetBytes("<llsd>undef</llsd>");
                    return;
                }

                // Get land data based on avatar's position
                LandData land = scene.GetLandData(avatar.AbsolutePosition);

                // Check if voice is allowed in the estate settings of the region
                if (!scene.RegionInfo.EstateSettings.AllowVoice)
                {
                    // Log a debug message and set an empty channel URI
                    m_log.DebugFormat("[TCPServerVoice][PARCELVOICE]: region \"{0}\": voice not enabled in estate settings", scene.RegionInfo.RegionName);
                    channelUri = String.Empty;
                }
                else if (!scene.RegionInfo.EstateSettings.TaxFree && (land.Flags & (uint)ParcelFlags.AllowVoiceChat) == 0)
                {
                    // If voice is not tax-free and the parcel does not allow voice chat, set an empty channel URI
                    channelUri = String.Empty;
                }
                else
                {
                    // Generate the channel URI based on the scene and land data
                    channelUri = ChannelUri(scene, land);
                }

                // Create LLSD XML data
                osUTF8 lsl = LLSDxmlEncode2.Start(512);
                LLSDxmlEncode2.AddMap(lsl);
                LLSDxmlEncode2.AddElem("parcel_local_id", land.LocalID, lsl);
                LLSDxmlEncode2.AddElem("region_name", scene.Name, lsl);
                LLSDxmlEncode2.AddMap("voice_credentials", lsl);
                LLSDxmlEncode2.AddElem("channel_uri", channelUri, lsl);
                LLSDxmlEncode2.AddEndMap(lsl);
                LLSDxmlEncode2.AddEndMap(lsl);

                // Set the response buffer with the encoded LLSD XML data
                response.RawBuffer = LLSDxmlEncode2.EndToBytes(lsl);
            }
            catch (Exception e)
            {
                // Log an error message and set response with an undefined LLSD in case of an exception
                m_log.ErrorFormat("[TCPServerVoice][PARCELVOICE]: region \"{0}\": avatar \"{1}\": {2}, retry later", scene.RegionInfo.RegionName, avatarName, e.Message);
                m_log.DebugFormat("[TCPServerVoice][PARCELVOICE]: region \"{0}\": avatar \"{1}\": {2} failed", scene.RegionInfo.RegionName, avatarName, e.ToString());

                response.RawBuffer = Util.UTF8.GetBytes("<llsd>undef</llsd>");
            }
        }


        public string ChatSessionRequest(Scene scene, string request, string path, string param, UUID agentID, Caps caps)
        {
            // Get the avatar (scene presence) by agent ID
            ScenePresence avatar = scene.GetScenePresence(agentID);

            // Get the avatar's name
            string avatarName = avatar.Name;

            // Log a debug message with information about the request
            m_log.DebugFormat("[TCPServerVoice][CHATSESSION]: avatar \"{0}\": request: {1}, path: {2}, param: {3}", avatarName, request, path, param);

            // Return a simple LLSD response (in this case, always returning "<llsd>true</llsd>")
            return "<llsd>true</llsd>";
        }

        public Hashtable ForwardProxyRequest(Hashtable request)
        {
            // Log a debug message indicating the start of proxying
            m_log.Debug("[PROXYING]: -------------------------------proxying request");

            // Create a response hashtable
            Hashtable response = new Hashtable();

            // Set initial response properties
            response["content_type"] = "text/xml";
            response["str_response_string"] = "";
            response["int_response_code"] = 200;

            // Define the forward address (the URL to forward the request to)
            string forwardaddress = "https://www.bhr.vivox.com/api2/";

            // Extract various request parameters
            string body = (string)request["body"];
            string method = (string)request["http-method"];
            string contenttype = (string)request["content-type"];
            string uri = (string)request["uri"];
            uri = uri.Replace("/api/", "");
            forwardaddress += uri;

            string fwdresponsestr = "";
            int fwdresponsecode = 200;
            string fwdresponsecontenttype = "text/xml";

            // Create a HttpWebRequest for forwarding the request
            HttpWebRequest forwardreq = (HttpWebRequest)WebRequest.Create(forwardaddress);
            forwardreq.Method = method;
            forwardreq.ContentType = contenttype;
            forwardreq.KeepAlive = false;
            forwardreq.ServerCertificateValidationCallback = CustomCertificateValidation;

            // If the request method is POST, send the request body
            if (method == "POST")
            {
                byte[] contentreq = Util.UTF8.GetBytes(body);
                forwardreq.ContentLength = contentreq.Length;
                Stream reqStream = forwardreq.GetRequestStream();
                reqStream.Write(contentreq, 0, contentreq.Length);
                reqStream.Close();
            }

            // Send the request and handle the response
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

            // Update the response hashtable with the forwarded response properties
            response["content_type"] = fwdresponsecontenttype;
            response["str_response_string"] = fwdresponsestr;
            response["int_response_code"] = fwdresponsecode;

            // Return the response hashtable
            return response;
        }


        public Hashtable TCPServerSLVoiceGetPreloginHTTPHandler(Hashtable request)
        {
            // Create a response hashtable
            Hashtable response = new Hashtable();

            // Set initial response properties
            response["content_type"] = "text/xml";
            response["keepalive"] = false;

            // Construct an XML response string
            response["str_response_string"] = String.Format(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" +
                "<VCConfiguration>\r\n" +
                    "<DefaultRealm>{0}</DefaultRealm>\r\n" +
                    "<DefaultSIPProxy>{1}</DefaultSIPProxy>\r\n" +
                    "<DefaultAttemptUseSTUN>{2}</DefaultAttemptUseSTUN>\r\n" +
                    "<DefaultEchoServer>{3}</DefaultEchoServer>\r\n" +
                    "<DefaultEchoPort>{4}</DefaultEchoPort>\r\n" +
                    "<DefaultWellKnownIP>{5}</DefaultWellKnownIP>\r\n" +
                    "<DefaultTimeout>{6}</DefaultTimeout>\r\n" +
                    "<UrlResetPassword>{7}</UrlResetPassword>\r\n" +
                    "<UrlPrivacyNotice>{8}</UrlPrivacyNotice>\r\n" +
                    "<UrlEulaNotice/>\r\n" +
                    "<App.NoBottomLogo>false</App.NoBottomLogo>\r\n" +
                "</VCConfiguration>",
                m_tCPServerRealm, m_tCPServerSIPProxy, m_tCPServerAttemptUseSTUN,
                m_tCPServerEchoServer, m_tCPServerEchoPort,
                m_tCPServerDefaultWellKnownIP, m_tCPServerDefaultTimeout,
                m_tCPServerUrlResetPassword, "");

            // Set the response code to 200 (OK)
            response["int_response_code"] = 200;

            return response;
        }

        public Hashtable TCPServerSLVoiceBuddyHTTPHandler(Hashtable request)
        {
            // Log a debug message indicating the method call
            m_log.Debug("[TCPServerVoice]: TCPServerSLVoiceBuddyHTTPHandler called");

            // Create a response hashtable
            Hashtable response = new Hashtable();

            // Set the response code to 200 (OK)
            response["int_response_code"] = 200;

            // Initialize the response string as empty
            response["str_response_string"] = string.Empty;

            // Set the content type of the response
            response["content-type"] = "text/xml";

            // Parse the request body to extract information
            Hashtable requestBody = ParseRequestBody((string)request["body"]);

            // If the request body does not contain "auth_token," return the response as is
            if (!requestBody.ContainsKey("auth_token"))
                return response;

            // Extract the "auth_token" from the request body
            string auth_token = (string)requestBody["auth_token"];
            int strcount = 0;

            // Initialize an array to store IDs
            string[] ids = new string[strcount];

            int iter = -1;

            // Lock to prevent concurrent access to m_UUIDName dictionary
            lock (m_UUIDName)
            {
                // Get the count of entries in the dictionary
                strcount = m_UUIDName.Count;
                ids = new string[strcount];

                // Populate the "ids" array with dictionary keys
                foreach (string s in m_UUIDName.Keys)
                {
                    iter++;
                    ids[iter] = s;
                }
            }

            // Create a StringBuilder to construct the XML response
            StringBuilder resp = new StringBuilder();
            resp.Append("<?xml version=\"1.0\" encoding=\"iso-8859-1\" ?><response xmlns=\"http://www.vivox.com\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation= \"/xsd/buddy_list.xsd\">");

            // Construct the XML response with buddy list information
            resp.Append(string.Format(@"<level0>
                <status>OK</status>
                <cookie_name>lib_session</cookie_name>
                <cookie>{0}</cookie>
                <auth_token>{0}</auth_token>
                <body>
                    <buddies>", auth_token));

            for (int i = 0; i < ids.Length; i++)
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
                        </level3>", ids[i], i, m_tCPServerRealm, dt));
            }

            resp.Append("</buddies><groups></groups></body></level0></response>");

            // Set the constructed XML response as the response string
            response["str_response_string"] = resp.ToString();

            return response;
        }


        public Hashtable TCPServerSLVoiceWatcherHTTPHandler(Hashtable request)
        {
            // Log a debug message indicating the method call
            m_log.Debug("[TCPServerVoice]: TCPServerSLVoiceWatcherHTTPHandler called");

            // Create a response hashtable
            Hashtable response = new Hashtable();

            // Set the response code to 200 (OK)
            response["int_response_code"] = 200;

            // Set the content type of the response
            response["content-type"] = "text/xml";

            // Parse the request body to extract information
            Hashtable requestBody = ParseRequestBody((string)request["body"]);

            // Extract the "auth_token" from the request body
            string auth_token = (string)requestBody["auth_token"];

            // Create a StringBuilder to construct the XML response
            StringBuilder resp = new StringBuilder();
            resp.Append("<?xml version=\"1.0\" encoding=\"iso-8859-1\" ?><response xmlns=\"http://www.vivox.com\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation= \"/xsd/buddy_list.xsd\">");

            // Construct the XML response with authentication information
            resp.Append(string.Format(@"<level0>
                <status>OK</status>
                <cookie_name>lib_session</cookie_name>
                <cookie>{0}</cookie>
                <auth_token>{0}</auth_token>
                <body/></level0></response>", auth_token));

            // Set the constructed XML response as the response string
            response["str_response_string"] = resp.ToString();

            return response;
        }

        public Hashtable TCPServerSLVoiceSigninHTTPHandler(Hashtable request)
        {
            // Parse the request body to extract information
            Hashtable requestBody = ParseRequestBody((string)request["body"]);

            // Extract the "userid" from the request body
            string userid = (string)requestBody["userid"];

            // Initialize avatarName as an empty string and pos as -1
            string avatarName = string.Empty;
            int pos = -1;

            // Lock to prevent concurrent access to m_UUIDName dictionary
            lock (m_UUIDName)
            {
                // Check if the userid exists in the dictionary
                if (m_UUIDName.ContainsKey(userid))
                {
                    // Get the avatarName associated with the userid
                    avatarName = m_UUIDName[userid];

                    // Iterate through dictionary keys to find the position (index) of the userid
                    foreach (string s in m_UUIDName.Keys)
                    {
                        pos++;
                        if (s == userid)
                            break;
                    }
                }
            }

            // Create a response hashtable
            Hashtable response = new Hashtable();

            // Construct the XML response with authentication information
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

            // Set the response code to 200 (OK)
            response["int_response_code"] = 200;

            return response;
        }


        public Hashtable ParseRequestBody(string body)
        {
            // Create a hashtable to store key-value pairs parsed from the request body
            Hashtable bodyParams = new Hashtable();

            // Split the body into name-value pairs based on '&'
            string[] nvps = body.Split(new Char[] { '&' });

            foreach (string s in nvps)
            {
                // Skip empty entries
                if (s.Trim() != "")
                {
                    // Split the name-value pair into its components based on '='
                    string[] nvp = s.Split(new Char[] { '=' });

                    // Add the decoded key-value pair to the hashtable
                    bodyParams.Add(HttpUtility.UrlDecode(nvp[0]), HttpUtility.UrlDecode(nvp[1]));
                }
            }

            // Return the parsed key-value pairs as a hashtable
            return bodyParams;
        }

        private string ChannelUri(Scene scene, LandData land)
        {
            string channelUri = null;

            string landUUID;
            string landName;

            lock (m_ParcelAddress)
            {
                // Check if the parcel address for the land exists in the dictionary
                if (m_ParcelAddress.ContainsKey(land.GlobalID.ToString()))
                {
                    // Return the cached parcel address
                    m_log.DebugFormat("[TCPServerVoice]: parcel id {0}: using sip address {1}", land.GlobalID, m_ParcelAddress[land.GlobalID.ToString()]);
                    return m_ParcelAddress[land.GlobalID.ToString()];
                }
            }

            if (land.LocalID != 1 && (land.Flags & (uint)ParcelFlags.UseEstateVoiceChan) == 0)
            {
                // Construct a landName based on region and parcel information
                landName = String.Format("{0}:{1}", scene.RegionInfo.RegionName, land.Name);
                landUUID = land.GlobalID.ToString();
                m_log.DebugFormat("[TCPServerVoice]: Region:Parcel \"{0}\": parcel id {1}: using channel name {2}", landName, land.LocalID, landUUID);
            }
            else
            {
                // Use the region name as landName when it's parcel ID 1 or Estate voice is enabled
                landName = String.Format("{0}:{1}", scene.RegionInfo.RegionName, scene.RegionInfo.RegionName);
                landUUID = scene.RegionInfo.RegionID.ToString();
                m_log.DebugFormat("[TCPServerVoice]: Region:Parcel \"{0}\": parcel id {1}: using channel name {2}", landName, land.LocalID, landUUID);
            }

            // Construct the channel URI based on landUUID and realm
            channelUri = String.Format("sip:conf-{0}@{1}", "x" + Convert.ToBase64String(Encoding.ASCII.GetBytes(landUUID)), m_tCPServerRealm);

            lock (m_ParcelAddress)
            {
                // Cache the parcel address to avoid recomputation
                if (!m_ParcelAddress.ContainsKey(land.GlobalID.ToString()))
                {
                    m_ParcelAddress.Add(land.GlobalID.ToString(), channelUri);
                }
            }

            // Return the constructed channel URI
            return channelUri;
        }

        // Custom certificate validation method to accept any certificate
        private static bool CustomCertificateValidation(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors error)
        {
            // Always return true to accept any certificate
            return true;
        }


        public Hashtable TCPServerConfigHTTPHandler(Hashtable request)
        {
            // Create a response hashtable with initial values
            Hashtable response = new Hashtable();
            response["str_response_string"] = string.Empty;
            response["content_type"] = "text/plain";
            response["keepalive"] = false;
            response["int_response_code"] = 500;

            // Parse the request body to extract information
            Hashtable requestBody = ParseRequestBody((string)request["body"]);

            // Extract the "section" from the request body
            string section = (string)requestBody["section"];

            // Check the section to determine the type of configuration request
            if (section == "directory")
            {
                // If the section is "directory," extract and log the event calling function
                string eventCallingFunction = (string)requestBody["Event-Calling-Function"];
                m_log.DebugFormat("[TCPServerVoice]: Received request for config section directory, event calling function '{0}'", eventCallingFunction);

                // Call the HandleDirectoryRequest method of the TCPServerService to handle the request
                response = m_TCPServerService.HandleDirectoryRequest(requestBody);
            }
            else if (section == "dialplan")
            {
                // If the section is "dialplan," log the request
                m_log.DebugFormat("[TCPServerVoice]: Received request for config section dialplan");

                // Call the HandleDialplanRequest method of the TCPServerService to handle the request
                response = m_TCPServerService.HandleDialplanRequest(requestBody);
            }
            else
            {
                // If an unknown section is requested, log a warning
                m_log.WarnFormat("[TCPServerVoice]: Unknown section {0} was requested from config.", section);
            }

            // Return the response hashtable
            return response;
        }

    }

    // This is an internal interface for a TCP server service.
    internal class ITCPServerService
    {
        // Method to get JSON configuration (not implemented).
        internal string GetJsonConfig()
        {
            throw new NotImplementedException();
        }

        // Method to handle a dialplan request (not implemented).
        internal Hashtable HandleDialplanRequest(Hashtable requestBody)
        {
            throw new NotImplementedException();
        }

        // Method to handle a directory request (not implemented).
        internal Hashtable HandleDirectoryRequest(Hashtable requestBody)
        {
            throw new NotImplementedException();
        }
    }

    // This is the main TCP server class that implements ISharedRegionModule and IVoiceModule.
    public class TCPServer : ISharedRegionModule, IVoiceModule
    {
        public TCPServer()
        {
            // Constructor for TCPServer.
        }

        private IPEndPoint m_endpoint;
        private TcpListener m_tcpip;
        private Thread m_ThreadMainServer;
        private ListenerState m_State;

        private List<ServerThread> m_threads = new List<ServerThread>();

        // Delegates and events for client connection and data handling.
        public delegate void DelegateClientConnected(ServerThread st);
        public delegate void DelegateClientDisconnected(ServerThread st, string info);
        public delegate void DelegateDataReceived(ServerThread st, Byte[] data);

        public event DelegateClientConnected ClientConnected;
        public event DelegateClientDisconnected ClientDisconnected;
        public event DelegateDataReceived DataReceived;

        // Enumeration for the listener state.
        public enum ListenerState
        {
            None,
            Started,
            Stopped,
            Error
        };

        // Properties to access server state and client list.
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

        // Implementation of IRegionModuleBase.Name (not implemented).
        string IRegionModuleBase.Name => throw new NotImplementedException();

        // Implementation of IRegionModuleBase.ReplaceableInterface (not implemented).
        Type IRegionModuleBase.ReplaceableInterface => throw new NotImplementedException();

        // Start the TCP server with the given IP address and port.
        public void Start(string strIPAddress, int Port)
        {
            m_endpoint = new IPEndPoint(IPAddress.Parse(strIPAddress), Port);
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

        // Main server thread function.
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

        // Method to send data to all connected clients.
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

        // Event handler for data received from a client.
        private void OnDataReceived(ServerThread st, Byte[] data)
        {
            if (DataReceived != null)
            {
                DataReceived(st, data);
            }
        }

        // Event handler for client disconnection.
        private void OnClientDisconnected(ServerThread st, string info)
        {
            m_threads.Remove(st);

            if (ClientDisconnected != null)
            {
                ClientDisconnected(st, info);
            }
        }

        // Event handler for client connection.
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

        // Stop the TCP server.
        public void Stop()
        {
            try
            {
                if (m_ThreadMainServer != null)
                {
                    m_ThreadMainServer.Abort();
                    System.Threading.Thread.Sleep(100);
                }

                for (IEnumerator en = m_threads.GetEnumerator(); en.MoveNext();)
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

        // Implementation of ISharedRegionModule.PostInitialise (not implemented).
        void ISharedRegionModule.PostInitialise()
        {
            throw new NotImplementedException();
        }

        // Implementation of IRegionModuleBase.Initialise (not implemented).
        void IRegionModuleBase.Initialise(IConfigSource source)
        {
            throw new NotImplementedException();
        }

        // Implementation of IRegionModuleBase.Close (not implemented).
        void IRegionModuleBase.Close()
        {
            throw new NotImplementedException();
        }

        // Implementation of IRegionModuleBase.AddRegion (not implemented).
        void IRegionModuleBase.AddRegion(Scene scene)
        {
            throw new NotImplementedException();
        }

        // Implementation of IRegionModuleBase.RemoveRegion (not implemented).
        void IRegionModuleBase.RemoveRegion(Scene scene)
        {
            throw new NotImplementedException();
        }

        // Implementation of IRegionModuleBase.RegionLoaded (not implemented).
        void IRegionModuleBase.RegionLoaded(Scene scene)
        {
            throw new NotImplementedException();
        }

        // Implementation of IVoiceModule.setLandSIPAddress (not implemented).
        void IVoiceModule.setLandSIPAddress(string SIPAddress, UUID GlobalID)
        {
            throw new NotImplementedException();
        }
    }

    // This class represents a server thread for handling client connections.
    public class ServerThread
    {
        private bool m_IsStopped = false;
        private TcpClient m_Connection = null;
        public byte[] ReadBuffer = new byte[1024];
        public bool IsMute = false;
        public String Name = "";

        // Delegates and events for data received and client disconnection.
        public delegate void DelegateDataReceived(ServerThread st, Byte[] data);
        public event DelegateDataReceived DataReceived;
        public delegate void DelegateClientDisconnected(ServerThread sv, string info);
        public event DelegateClientDisconnected ClientDisconnected;

        // Property to access the client connection.
        public TcpClient Client
        {
            get
            {
                return m_Connection;
            }
        }

        // Property to check if the server thread is stopped.
        public bool IsStopped
        {
            get
            {
                return m_IsStopped;
            }
        }

        // Constructor for ServerThread.
        public ServerThread(TcpClient connection)
        {
            this.m_Connection = connection;
        }

        // Receive data from the client.
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

        // Handle client disconnection.
        public void HandleDisconnection(string reason)
        {
            m_IsStopped = true;

            if (ClientDisconnected != null)
            {
                ClientDisconnected(this, reason);
            }
        }

        // Send data to the client.
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

        // Stop the server thread.
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
