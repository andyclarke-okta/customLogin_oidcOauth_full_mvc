using log4net;
using Okta.Core;
using Okta.Core.Clients;
using Okta.Core.Models;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;
using System.Threading;

using Newtonsoft.Json.Linq;

using OIDC_CustomLogin.Models;

using System.Collections;
using System.Diagnostics;

using System.Web.Mvc;

using System.Collections.Specialized;
using System.Net.Http;
using System.Threading.Tasks;

using Newtonsoft.Json;
using System.Text;
using System.IO;
using System.Web.UI;

namespace OIDC_CustomLogin.Services
{
    public class OktaAPIHelper
    {
        private OktaSettings _orgSettings;
        private string _apiToken;
        private string _orgUrl;
        private AuthClient _authclient;
        private UsersClient _usersClient;
        private OktaClient _oktaClient;
        private SessionsClient _sessionsClient;
        private UserFactorsClient _userFactorClient;


        private static ILog _logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        public OktaAPIHelper(string orgUrlParam, string apiToken)
        {
            _orgUrl = orgUrlParam;
            Uri orgUri = new Uri(OrgUrl);
            _orgSettings = new OktaSettings();
            _orgSettings.ApiToken = apiToken;
            _orgSettings.BaseUri = orgUri;
            _authclient = new AuthClient(_orgSettings);
            _oktaClient = new OktaClient(_orgSettings);
            _usersClient = new UsersClient(_orgSettings);
            _sessionsClient = new SessionsClient(_orgSettings);

        }

        public string OrgUrl { get { return _orgUrl; } }


        public bool RateLimitCheck(IRestResponse response)
        {
            string limitMod = null;
            string remainingMod = null;
            string resetMod = null;
            var headerList = response.Headers.ToList();
            string limit = headerList.Find(x => x.Name == "X-Rate-Limit-Limit").Value.ToString();
            string remaining = headerList.Find(x => x.Name == "X-Rate-Limit-Remaining").Value.ToString();
            string reset = headerList.Find(x => x.Name == "X-Rate-Limit-Reset").Value.ToString();

            int limitIndex = limit.IndexOf(",");
            if (limitIndex > 0)
            {
                limitMod = limit.Substring(0, limitIndex);
            }
            else
            {
                limitMod = limit;
            }

            int remainingIndex = remaining.IndexOf(",");
            if (remainingIndex > 0)
            {
                remainingMod = remaining.Substring(0, remainingIndex);
            }
            else
            {
                remainingMod = remaining;
            }

            int resetIndex = reset.IndexOf(",");
            if (resetIndex > 0)
            {
                resetMod = reset.Substring(0, resetIndex);
            }
            else
            {
                resetMod = reset;
            }


            int myLimit = Convert.ToInt32(limitMod);
            int myRemaining = Convert.ToInt32(remainingMod);
            int myReset = Convert.ToInt32(resetMod);

            // Parse the string header to an int

            int waitUntilUnixTime;
            if (!int.TryParse(resetMod, out waitUntilUnixTime))
            {
                _logger.Error("unable to calculate wait time");
            }
            // See how long until we hit that time
            var unixTime = (Int64)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds;
            //var millisToWait = unixTime - ((Int64)waitUntilUnixTime * 1000);
            var millisToWait = ((Int64)waitUntilUnixTime * 1000) - unixTime;


            _logger.Debug(" Limit Config:" + limitMod + " Remaining:" + remainingMod + " Epoch sec " + unixTime / 1000 + " ResetTime_sec:" + resetMod + " millisToWait:" + millisToWait);

            if (millisToWait >= 100)
            {
                //logger.Debug(" wait for " + myReset.ToString());
                // wait the reset time then return true to recylce the command
                WaitTimer(millisToWait);
            }
            return true;

        }

        public void WaitTimer(Int64 milliseconds)
        {
            //logger.Debug("wait " + milliseconds);
            //delay before checking
            //provide time for user to respond
            //int milliseconds = 3000;
            //int milliseconds = Convert.ToInt32("3000");
            if (milliseconds > 0)
            {
                // Cross platform sleep
                using (var mre = new ManualResetEvent(false))
                {
                    mre.WaitOne((int)milliseconds);
                }
            }
            return;
        }


        public string CheckCountryCode(string countryCode)
        {
            ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
            NameValueCollection appSettings = ConfigurationManager.AppSettings;
            logger.Debug("CheckCountryCode");


            // read in json file
            string countryPrefix;
            string CountryCodeJsonFile = appSettings["custom.countryCode_json"];
            string path = AppDomain.CurrentDomain.GetData("DataDirectory").ToString();
            string fullPath = path + "\\" + CountryCodeJsonFile;
            JArray jsonInput = new JArray();
            try
            {
                jsonInput = JArray.Parse(System.IO.File.ReadAllText(fullPath));
            }
            catch (Exception ex)
            {
                logger.Error(ex);

                //return null;
            }

            // lookup affiliate properties
            var codeQuery = (from p in jsonInput
                             where p.SelectToken("countryCode").Value<string>() == countryCode
                             select new
                             {
                                 Prefix = (string)p["prefix"]
                             }
            );
            try
            {
                // set affiliate object
                countryPrefix = codeQuery.First().Prefix;
                logger.Debug("Country Code  found ");
            }
            catch (Exception)
            {
                logger.Debug("Country Code  not retrieved");

                return null;
            }

            return countryPrefix;
        }

        //public SmsCountryCodeList GetCountryCodes()
        //{
        //    ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        //    NameValueCollection appSettings = ConfigurationManager.AppSettings;
        //    logger.Debug("SmsCountryCodeList");

        //    // read in json file
        //    SmsCountryCodeList smsCountryCodeList = new SmsCountryCodeList();
        //    smsCountryCodeList.codeList = new List<SmsCountryCode>();
        //    string CountryCodeJsonFile = appSettings["custom.countryCode_json"];
        //    string path = AppDomain.CurrentDomain.GetData("DataDirectory").ToString();
        //    string fullPath = path + "\\" + CountryCodeJsonFile;
        //    JArray jsonArrayInput = new JArray();
        //    JObject jsonObjectInput = new JObject();
        //    try
        //    {
        //        jsonArrayInput = JArray.Parse(System.IO.File.ReadAllText(fullPath));
        //    }
        //    catch (Exception ex)
        //    {
        //        logger.Error(ex);

        //        //return null;
        //    }

        //    List<SmsCountryCode> myCountryCodes = new List<SmsCountryCode>();
        //    myCountryCodes = jsonArrayInput.ToObject<List<SmsCountryCode>>();

        //    foreach (SmsCountryCode code in myCountryCodes)
        //    {
        //        smsCountryCodeList.codeList.Add(new SmsCountryCode() { countryCode = code.countryCode, prefix = code.prefix, countryName = code.countryName });
        //    }

        //    return smsCountryCodeList;
        //}


        public string RenderPartialToString(ControllerContext controllerContext, string p, ViewDataDictionary ViewData, TempDataDictionary TempData)
        {

            ViewEngineResult result = ViewEngines.Engines.FindPartialView(controllerContext, p);

            if (result.View != null)
            {

                StringBuilder sb = new StringBuilder();
                using (StringWriter sw = new StringWriter(sb))
                {
                    using (HtmlTextWriter output = new HtmlTextWriter(sw))
                    {
                        ViewContext viewContext = new ViewContext(controllerContext, result.View, ViewData, TempData, output);
                        result.View.Render(viewContext, output);
                    }
                }

                return sb.ToString();
            }
            return String.Empty;
        }



        //public static IdentityProviderList GetIdentityProviderList()
        //{
        //    ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        //    NameValueCollection appSettings = ConfigurationManager.AppSettings;
        //    logger.Debug("GetHelpDeskQuestionList");

        //    IdentityProviderList identityProviderList = new IdentityProviderList();
        //    identityProviderList.identityProviderConfig = new List<IdentityProviderConfig>();
        //    string identityProviderJsonFile = appSettings["okta.identityProvider_json"];

        //    string path = AppDomain.CurrentDomain.GetData("DataDirectory").ToString();
        //    string fullPath = path + "\\" + identityProviderJsonFile;
        //    JArray jsonArrayInput = new JArray();
        //    JObject jsonObjectInput = new JObject();
        //    try
        //    {
        //        jsonArrayInput = JArray.Parse(System.IO.File.ReadAllText(fullPath));
        //    }
        //    catch (Exception ex)
        //    {
        //        logger.Error(ex);

        //        //return null;
        //    }

        //    List<IdentityProviderConfig> myIDP = new List<IdentityProviderConfig>();
        //    myIDP = jsonArrayInput.ToObject<List<IdentityProviderConfig>>();

        //    foreach (IdentityProviderConfig item in myIDP)
        //    {
        //        identityProviderList.identityProviderConfig.Add(new IdentityProviderConfig { idpName = item.idpName, idpDomain = item.idpDomain, idpUrl = item.idpUrl, idpACS = item.idpACS, idpApp = item.idpApp });
        //    }

        //    return identityProviderList;
        //}

        public bool SendRequestToWebApi_NoToken(string destPage)
        {
            _logger.Debug("SendRequestToWebApiA_NoToken");
            IRestResponse response = null;

            var client = new RestClient(destPage);
            var request = new RestRequest(Method.GET);
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");

            response = client.Execute(request);
            if (response.StatusDescription == "OK")
            {
                return true;
            }
            else
            {
                return false;
            }
        }

    }
}