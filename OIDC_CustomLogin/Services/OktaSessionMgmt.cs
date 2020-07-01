using log4net;
using Okta.Core;
using Okta.Core.Clients;
using Okta.Core.Models;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;

using Newtonsoft.Json.Linq;
using OIDC_CustomLogin.Models;
using System.Collections;
using System.Diagnostics;
using System.Web.Mvc;
using System.Collections.Specialized;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using Newtonsoft.Json;
using System.Text;
using System.IO;
using System.Web.UI;
using RestSharp;

namespace OIDC_CustomLogin.Services
{
    public class OktaSessionMgmt
    {

        private OktaSettings _orgSettings;
        private string _apiToken;
        private string _apiUrl;
        private AuthClient _authclient;
        private UsersClient _usersClient;
        private OktaClient _oktaClient;
        private SessionsClient _sessionsClient;
        private UserFactorsClient _userFactorClient;


        private static ILog _logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        public OktaSessionMgmt(string apiUrl, string apiToken)
        {
            _apiUrl = apiUrl;
            Uri orgUri = new Uri(OrgUrl);
            _orgSettings = new OktaSettings();
            _orgSettings.ApiToken = apiToken;
            _orgSettings.BaseUri = orgUri;
            _authclient = new AuthClient(_orgSettings);
            _oktaClient = new OktaClient(_orgSettings);
            _usersClient = new UsersClient(_orgSettings);
            _sessionsClient = new SessionsClient(_orgSettings);

        }


        public string OrgUrl { get { return _apiUrl; } }

        public Session CreateSession(string sessionToken)
        {
            return _sessionsClient.CreateSession(sessionToken);
        }

        public Session GetOktaSession(string sessionId)
        {
            return _sessionsClient.Validate(sessionId);
        }

        public bool CloseSession(string sessionId)
        {
            bool result = false;
            try
            {
                _sessionsClient.Close(sessionId);
                result = true;
            }
            catch
            {
                // log exception
            }

            return result;
        }


        //public string SessionRedirect(string sessionToken, string destinationUrl)
        //{
        //    // build redirectURL
        //    System.Text.StringBuilder redirectURL = new System.Text.StringBuilder();

        //    redirectURL.Append(OrgUrl);
        //    redirectURL.Append("/login/sessionCookieRedirect?token=" + sessionToken);

        //    string destLink = OrgUrl;  // Assign  Org Base URL

        //    if (!string.IsNullOrEmpty(destinationUrl))
        //    {
        //        redirectURL.Append(string.Format("&redirectUrl={0}", destinationUrl));
        //    }

        //    return redirectURL.ToString();                                       // Encoding is nice
        //}

        public string LogoutRedirect(string destinationUrl)
        {
            // build redirectURL
            System.Text.StringBuilder redirectURL = new System.Text.StringBuilder();

            redirectURL.Append(OrgUrl);
            redirectURL.Append("/login/signout");

            string destLink = OrgUrl;  // Assign  Org Base URL

            if (!string.IsNullOrEmpty(destinationUrl))
            {
                redirectURL.Append(string.Format("?redirectUrl={0}", destinationUrl));
            }

            return redirectURL.ToString();                                       // Encoding is nice
        }

        public string SetSessionCookie(string sessionToken, string relayState)
        {
            string encodedURL = null;
            string destLink = null;
            // build redirectURL
            System.Text.StringBuilder redirectURL = null;

            if (!string.IsNullOrEmpty(sessionToken))
            {
                // build redirectURL
                redirectURL = new System.Text.StringBuilder();

                redirectURL.Append(_apiUrl);
                redirectURL.Append("/login/sessionCookieRedirect?token=" + sessionToken);


                if (string.IsNullOrEmpty(relayState))
                {
                    destLink = _apiUrl.ToString();
                    encodedURL = HttpUtility.UrlEncode(destLink);
                }
                else
                {
                    //encodedURL = HttpUtility.UrlEncode(relayState);
                    encodedURL = relayState;
                }

                redirectURL.Append("&redirectUrl=" + encodedURL);
                return redirectURL.ToString();
            }
            else
            {
                // some paths such as Unlock Account dont end with a sessionToken
                return null;
            }


        }

    }
}