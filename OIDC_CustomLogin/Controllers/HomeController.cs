using log4net;
using Okta.Core.Models;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OIDC_CustomLogin.Models;
using OIDC_CustomLogin.Services;
using Okta.Core;
using Okta.Core.Clients;

namespace OIDC_CustomLogin.Controllers
{
    public class HomeController : Controller
    {

        ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        // ILog logger = LogManager.GetLogger("SpecialLogFile");

        NameValueCollection appSettings = ConfigurationManager.AppSettings;

        private OktaSettings _orgSettings;
        private AuthClient _authClient;
        private UsersClient _usersClient;
        private OktaClient _oktaClient;

        // Org settings for primary Org
        private static string apiUrl = ConfigurationManager.AppSettings["okta.apiUrl"];
        private static string apiToken = ConfigurationManager.AppSettings["okta.apiToken"];

        private OktaUserMgmt oktaUserMgmt = new OktaUserMgmt(apiUrl, apiToken);
        private OktaAuthMgmt oktaAuthMgmt = new OktaAuthMgmt(apiUrl, apiToken);
        private OktaSessionMgmt oktaSessionMgmt = new OktaSessionMgmt(apiUrl, apiToken);
        private OktaOidcHelper oktaOidcHelper = new OktaOidcHelper(apiUrl, apiToken);

        private CacheService cacheService = new CacheService();

        [HttpGet]
        public ActionResult Error()
        {
            logger.Debug("okta error message redirect");
            return View();
        }


        [HttpGet]
        public ActionResult Login()
        {
            //set relayState
            string relayState = Request["relayState"];
            if (string.IsNullOrEmpty(relayState) && Request.QueryString["RelayState"] != null)
            {
                relayState = Request.QueryString["RelayState"];
            }
            else if (string.IsNullOrEmpty(relayState) && TempData["relayState"] != null)
            {
                relayState = (string)TempData["relayState"];
            }
            TempData["relayState"] = relayState;
            TempData["oktaOrg"] = apiUrl;
            TempData["version"] = appSettings["okta.widgetVersion"];
            TempData["issuer"] = appSettings["oidc.issuer"];
            TempData["clientId"] = appSettings["oidc.spintweb.clientId"];
            TempData["redirectUri"] = appSettings["oidc.spintweb.redirectUri"];
            TempData["AuthServer"] = appSettings["oidc.authServer"];

            //Note: Native App Resource owner and PKCE needs config within tenant
            //return View("CustomLogin_ResourceOwner");
            //return View("Initiate_IDPuser");
            //return View("CustomLogin_Implicit");
            return View("CustomLogin_AuthCode");
            //return View("CustomLogin_PKCE");
            //return View("Initiate_ClientCred");
            //return View("WidgetLogin_Implicit");                                
            //return View("WidgetLogin_AuthCode");
        }



        [HttpPost]
        public ActionResult IDPRoute()
        {
            string location = Request["location"];
            // set relayState 
            string relayState = Request["relayState"];
            TempData["relayState"] = relayState;

            //this is available with Custom Authorization Server
            logger.Debug("using OIDC IDP for authnetication");

            //exchange sessionToken for sessionCookie in OIDC Implicit workflow
            Random random = new Random();
            string nonceValue = random.Next(99999, 1000000).ToString();
            string stateCode = "myStateInfo";
            string oauthUrl = appSettings["oidc.authServer"] + "/v1/authorize?idp=" + appSettings["okta.identityProvider"] + "&response_type=id_token token&response_mode=form_post&client_id=" + appSettings["oidc.spintweb.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateCode + " &nonce=" + nonceValue + "&redirect_uri=" + appSettings["oidc.spintweb.RedirectUri"];
            return Redirect(oauthUrl);
        }



        [HttpPost]
        public ActionResult ResourceOwnerRoute()
        {

            string userName = Request["userName"];
            string passWord = Request["passWord"];
            //string authnlogin_but = Request["authnlogin_but"];
            //string oidclogin_but = Request["oidclogin_but"];
            //string oidc_but = Request["oidc_but"];
            string location = Request["location"];
            // set relayState 
            string relayState = Request["relayState"];
            TempData["relayState"] = relayState;

            string error = null;
            string error_description = null;
            string token_type = null;
            string scope = null;
            string id_token_status = null;
            string idToken = null;
            string access_token_status = null;
            string accessToken = null;
            string refresh_token_status = null;
            string refreshToken = null;
            System.Security.Claims.ClaimsPrincipal jsonPayload = null;


            IRestResponse<TokenRequestResponse> response = null;
            OidcIdTokenMin oidcIdToken = new OidcIdTokenMin();
            OidcAccessToken oidcAccessToken = new OidcAccessToken();
            string basicAuth = appSettings["oidc.spintnative.clientId"] + ":" + appSettings["oidc.spintnative.clientSecret"];

            var bytesBasicAuth = System.Text.Encoding.UTF8.GetBytes(basicAuth);
            string encodedBasicAuth = System.Convert.ToBase64String(bytesBasicAuth);

            try
            {
                var client = new RestClient(appSettings["oidc.authServer"] + "/v1/token");
                var request = new RestRequest(Method.POST);
                request.AddHeader("Accept", "application/json");
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddHeader("Authorization", " Basic " + encodedBasicAuth);
                request.AddQueryParameter("grant_type", "password");
                request.AddQueryParameter("username", userName);
                request.AddQueryParameter("password", passWord);
                request.AddQueryParameter("scope", appSettings["oidc.scopes"]);
                response = client.Execute<TokenRequestResponse>(request);
                if (response.Data != null)
                {
                    error = response.Data.error;
                    error_description = response.Data.error_description;
                    token_type = response.Data.token_type;
                    scope = response.Data.scope;
                }

                if (response.Data.id_token != null)
                {
                    idToken = response.Data.id_token;
                    id_token_status = "id_token present";
                    TempData["idToken"] = response.Data.id_token;
                    string issuer = appSettings["oidc.issuer"];
                    string audience = appSettings["oidc.spintnative.clientId"];
                    //jsonPayload = oktaOidcHelper.DecodeAndValidateIdToken(idToken, clientId, issuer, audience);
                    jsonPayload = oktaOidcHelper.ValidateIdToken(idToken, issuer, audience);
                    if (jsonPayload.Identity.IsAuthenticated)
                    {
                        TempData["errMessage"] = jsonPayload.ToString();
                        //System.IdentityModel.Tokens.Jwt.JwtSecurityToken tokenReceived = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(idToken);
                        //oidcIdToken = Newtonsoft.Json.JsonConvert.DeserializeObject<OidcIdToken>(tokenReceived.ToString());
                    }
                    else
                    {
                        TempData["errMessage"] = "Invalid ID Token!";

                    }
                    TempData["idToken"] = idToken;
                }
                else
                {
                    id_token_status = "id_token NOT present";
                }

                if (response.Data.access_token != null)
                {
                    accessToken = response.Data.access_token;
                    access_token_status = "access_token present";
                    TempData["accessToken"] = response.Data.access_token;
                    //System.IdentityModel.Tokens.JwtSecurityToken tokenReceived2 = new System.IdentityModel.Tokens.JwtSecurityToken(accessToken);
                }
                else
                {
                    access_token_status = "access_token NOT present";
                }

                if (response.Data.refresh_token != null)
                {
                    refreshToken = response.Data.refresh_token;
                    refresh_token_status = "refresh_token present";
                }
                else
                {
                    refresh_token_status = "refresh_token NOT present";
                }

            }
            catch (Exception ex)
            {

                logger.Error(ex.ToString());
            }
            if (accessToken != null || idToken != null)
            {
                TempData["errMessage"] = "OIDC_Get Oauth Resource Owner SUCCESS token_type = " + token_type + " scope = " + scope + " : " + id_token_status + " : " + access_token_status + " oktaId = " + oidcIdToken.sub;
                TempData["oktaOrg"] = apiUrl;
      

                return View("../AltLanding/ResOwnerLanding", oidcIdToken);
            }
            else
            {
                TempData["errMessage"] = "OIDC_Get Oauth Resource Owner error " + error_description;
                TempData["oktaOrg"] = apiUrl;
                return View("../AltLanding/UnprotectedLanding");
            }
        }//end resource owner workflow


        [HttpPost]
        public ActionResult ClientCredRoute()
        {
            string location = Request["location"];
            // set relayState 
            string relayState = Request["relayState"];
            TempData["relayState"] = relayState;

            //this is available with Custom Authorization Server
            logger.Debug("Client Credential Flow");
            string error = null;
            string error_description = null;
            string token_type = null;
            string scope = null;
            string access_token_status = null;
            string accessToken = null;
            string expires = null;
            IRestResponse<TokenRequestResponse> response = null;
            OidcIdToken oidcIdToken = new OidcIdToken();
            OidcAccessToken oidcAccessToken = new OidcAccessToken();
            string basicAuth = appSettings["oidc.clientcredservice.clientId"] + ":" + appSettings["oidc.clientcredservice.clientSecret"];
            var bytesBasicAuth = System.Text.Encoding.UTF8.GetBytes(basicAuth);
            string encodedBasicAuth = System.Convert.ToBase64String(bytesBasicAuth);

            var client = new RestClient(appSettings["oidc.authServer"] + "/v1/token");
            var request = new RestRequest(Method.POST);
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
            request.AddHeader("Authorization", " Basic " + encodedBasicAuth);
            request.AddQueryParameter("grant_type", "client_credentials");
            request.AddQueryParameter("scope", appSettings["oidc.clientcredservice.scopes"]);
            //for inline hooks
            request.AddQueryParameter("extra_param", "F0384685-userInfo-2058AC5655A7");

            response = client.Execute<TokenRequestResponse>(request);
            if (response.Data != null)
            {
                error = response.Data.error;
                error_description = response.Data.error_description;
                token_type = response.Data.token_type;
                scope = response.Data.scope;
                expires = response.Data.expires_in;
            }

            if (response.Data.access_token != null)
            {
                accessToken = response.Data.access_token;
                access_token_status = "access_token present";
                TempData["accessToken"] = response.Data.access_token;
            }
            else
            {
                access_token_status = "access_token NOT present";
            }

            if (accessToken != null)
            {
                TempData["errMessage"] = "Oauth Client Credentials SUCCESS token_type = " + token_type + " expires " + expires + " scope = " + scope + "  : " + access_token_status;
                TempData["oktaOrg"] = apiUrl;

                return View("../AltLanding/ClientCredLanding");
            }
            else
            {
                TempData["errMessage"] = "Oauth Client Credentials Error token_type = " + token_type + " expires " + expires + " scope = " + scope + "  : " + access_token_status;
                TempData["oktaOrg"] = apiUrl;
                return View("../AltLanding/UnprotectedLanding");
            }

        }


        [HttpPost]
        public ActionResult ImplicitRoute()
        {
            string userName = Request["userName"];
            string passWord = Request["passWord"];
            string authnlogin_but = Request["authnlogin_but"];
            string oidclogin_but = Request["oidclogin_but"];
            string oidc_but = Request["oidc_but"];
            string location = Request["location"];
            string myStatus = null;
            string myStateToken;
            string mySessionToken;
            string myOktaId = null;
            AuthResponse userAuthClientRsp;

            // set relayState 
            string relayState = Request["relayState"];
            TempData["relayState"] = relayState;

            Uri orgUri = new Uri(apiUrl);
            _orgSettings = new OktaSettings();
            _orgSettings.ApiToken = apiToken;
            _orgSettings.BaseUri = orgUri;

            _oktaClient = new OktaClient(_orgSettings);
            _usersClient = new UsersClient(_orgSettings);
            _authClient = new AuthClient(_orgSettings);
            try
            {

                userAuthClientRsp = _authClient.Authenticate(username: userName, password: passWord, relayState: relayState);
                logger.Debug("thisAuth status " + userAuthClientRsp.Status);
                myStatus = userAuthClientRsp.Status;
                myStateToken = userAuthClientRsp.StateToken;
                mySessionToken = userAuthClientRsp.SessionToken;
                if (userAuthClientRsp.Embedded.User != null)
                {
                    myOktaId = userAuthClientRsp.Embedded.User.Id;
                }

            }
            catch (OktaException ex)
            {
                if (ex.ErrorCode == "E0000004")
                {
                    logger.Debug("Invalid Credentials for User: " + userName);
                    TempData["errMessage"] = "Invalid Credentials for User: " + userName;
                }
                else if (ex.ErrorCode == "E0000085")
                {
                    logger.Debug("Access Denied by Polciy for User: " + userName);
                    //   TempData["errMessage"] = "Access Denied by Polciy for User: " + userName;
                    TempData["errMessage"] = "Access Denied by Polciy for User: " + userName;
                }
                else
                {
                    logger.Error(userName + " = " + ex.ErrorCode + ":" + ex.ErrorSummary);
                    // generic failure
                    TempData["errMessage"] = "Sign in process failed!";
                }
                TempData["userName"] = userName;
                return RedirectToAction("Login");
            }

            switch (myStatus)
            {

                case "PASSWORD_WARN":  //password about to expire
                    logger.Debug("PASSWORD_WARN ");
                    break;
                case "PASSWORD_EXPIRED":  //password has expired
                    logger.Debug("PASSWORD_EXPIRED ");
                    break;

                case "RECOVERY":  //user has requested a recovery token
                    logger.Debug("RECOVERY ");
                    break;
                case "RECOVERY_CHALLENGE":  //user must verify factor specific recovery challenge
                    logger.Debug("RECOVERY_CHALLENGE ");
                    break;
                case "PASSWORD_RESET":     //user satified recovery and must now set password
                    logger.Debug("PASSWORD_RESET ");
                    break;
                case "LOCKED_OUT":  //user account is locked, unlock required
                    logger.Debug("LOCKED_OUT ");
                    break;
                case "MFA_ENROLL":   //user must select and enroll an available factor 
                    logger.Debug("MFA_ENROLL ");
                    break;
                case "MFA_ENROLL_ACTIVATE":   //user must activate the factor to complete enrollment
                    logger.Debug("MFA_ENROLL_ACTIVATE ");
                    break;
                case "MFA_REQUIRED":    //user must provide second factor with previously enrolled factor
                    logger.Debug("MFA_REQUIRED ");
                    break;

                case "MFA_CHALLENGE":      //use must verify factor specifc challenge
                    logger.Debug("MFA_CHALLENGE ");
                    break;

                case "SUCCESS":      //authentication is complete
                    logger.Debug("SUCCESS");
                    TempData["errMessage"] = "Authn Login Successful ";
                    TempData["oktaOrg"] = apiUrl;

                    string landingPage = null;
                    if (string.IsNullOrEmpty(relayState))
                    {
                        landingPage = location + "/AltLanding/UnprotectedLanding";
                    }
                    else
                    {
                        landingPage = relayState;
                    }

                    ////optionaly get session Id locally
                    //Session oktaSession = new Okta.Core.Models.Session();
                    //oktaSession = oktaSessionMgmt.CreateSession(mySessionToken);
                    //string cookieToken = oktaSession.CookieToken;
                    //logger.Debug("session Id " + oktaSession.Id + " for User " + userName);
                    //mySessionToken = cookieToken;

                    //exchange sessionToken for sessionCookie in OIDC Implicit workflow
                    Random random = new Random();
                    string nonceValue = random.Next(99999, 1000000).ToString();
                    string stateCode = "myStateInfo";
                    string oauthUrl = appSettings["oidc.authServer"] + "/v1/authorize?response_type=token id_token&response_mode=form_post&client_id=" + appSettings["oidc.spintweb.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateCode + " &nonce=" + nonceValue + "&redirect_uri=" + appSettings["oidc.spintweb.RedirectUri"] + "&sessionToken=" + mySessionToken;
                    //string oauthUrl = appSettings["oidc.authServer"] + "/v1/authorize?idp=0oak4qcg796eVYakY0h7&response_type=id_token token&response_mode=form_post&client_id=" + appSettings["oidc.spintweb.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateCode + " &nonce=" + nonceValue + "&redirect_uri=" + appSettings["oidc.spintweb.RedirectUri"] + "&sessionToken=" + mySessionToken;
                    return Redirect(oauthUrl);


                    //NOT Typical
                    //have idToken returned in response
                    //IRestResponse response = null;
                    //var client = new RestClient(MvcApplication.apiUrl + "/oauth2/v1/authorize");
                    //var request = new RestRequest(Method.GET);
                    //request.AddHeader("Accept", "application/json");
                    //request.AddHeader("Content-Type", "application/json");
                    ////request.AddHeader("Authorization", " SSWS " + MvcApplication.apiToken);
                    //request.AddQueryParameter("client_id", appSettings["oidc.spintweb.clientId"]);
                    //request.AddQueryParameter("response_type", "id_token");
                    ////request.AddQueryParameter("response_type", "token");
                    //request.AddQueryParameter("response_mode", "okta_post_message");
                    //request.AddQueryParameter("scope", "openid");
                    //request.AddQueryParameter("prompt", "none");
                    //request.AddQueryParameter("redirect_uri", appSettings["oidc.spintweb.RedirectUri"]);
                    //request.AddQueryParameter("state", "myStateInfo");
                    //request.AddQueryParameter("nonce", "myNonce");
                    //request.AddQueryParameter("sessionToken", mySessionToken);
                    //response = client.Execute(request);
                    //int myIndex_01 = response.Content.IndexOf("data.id_token =");
                    //string firstBreak = response.Content.Substring(myIndex_01 + 17);
                    //int myIndex_02 = firstBreak.IndexOf(";");
                    //int subLength = myIndex_02 - 1;
                    //string myIdToken = firstBreak.Substring(0, subLength);
                    //logger.Debug(myIdToken);
                    //ViewBag.HtmlStr = response.Content;
                    //return View("../AltLanding/MyContent");





                // break;
                default:
                    logger.Debug("Status: " + myStatus);
                    TempData["errMessage"] = "Status: " + myStatus;
                    break;
            }//end of switch
            TempData["userName"] = userName;

            return RedirectToAction("UnprotectedLanding", "AltLanding");
        }


        [HttpPost]
        public ActionResult AuthCodeRoute()
        {
            string userName = Request["userName"];
            string passWord = Request["passWord"];
            string authnlogin_but = Request["authnlogin_but"];
            string oidclogin_but = Request["oidclogin_but"];
            string oidc_but = Request["oidc_but"];
            string location = Request["location"];
            string myStatus = null;
            string myStateToken;
            string mySessionToken;
            string myOktaId = null;
            AuthResponse userAuthClientRsp;

            // set relayState 
            string relayState = Request["relayState"];
            TempData["relayState"] = relayState;

            Uri orgUri = new Uri(apiUrl);
            _orgSettings = new OktaSettings();
            _orgSettings.ApiToken = apiToken;
            _orgSettings.BaseUri = orgUri;

            _oktaClient = new OktaClient(_orgSettings);
            _usersClient = new UsersClient(_orgSettings);
            _authClient = new AuthClient(_orgSettings);
            try
            {

                userAuthClientRsp = _authClient.Authenticate(username: userName, password: passWord, relayState: relayState);
                logger.Debug("thisAuth status " + userAuthClientRsp.Status);
                myStatus = userAuthClientRsp.Status;
                myStateToken = userAuthClientRsp.StateToken;
                mySessionToken = userAuthClientRsp.SessionToken;
                if (userAuthClientRsp.Embedded.User != null)
                {
                    myOktaId = userAuthClientRsp.Embedded.User.Id;
                }

            }
            catch (OktaException ex)
            {
                if (ex.ErrorCode == "E0000004")
                {
                    logger.Debug("Invalid Credentials for User: " + userName);
                    TempData["errMessage"] = "Invalid Credentials for User: " + userName;
                }
                else if (ex.ErrorCode == "E0000085")
                {
                    logger.Debug("Access Denied by Polciy for User: " + userName);
                    //   TempData["errMessage"] = "Access Denied by Polciy for User: " + userName;
                    TempData["errMessage"] = "Access Denied by Polciy for User: " + userName;
                }
                else
                {
                    logger.Error(userName + " = " + ex.ErrorCode + ":" + ex.ErrorSummary);
                    // generic failure
                    TempData["errMessage"] = "Sign in process failed!";
                }
                TempData["userName"] = userName;
                return RedirectToAction("Login");
            }

            switch (myStatus)
            {

                case "PASSWORD_WARN":  //password about to expire
                    logger.Debug("PASSWORD_WARN ");
                    break;
                case "PASSWORD_EXPIRED":  //password has expired
                    logger.Debug("PASSWORD_EXPIRED ");
                    break;

                case "RECOVERY":  //user has requested a recovery token
                    logger.Debug("RECOVERY ");
                    break;
                case "RECOVERY_CHALLENGE":  //user must verify factor specific recovery challenge
                    logger.Debug("RECOVERY_CHALLENGE ");
                    break;
                case "PASSWORD_RESET":     //user satified recovery and must now set password
                    logger.Debug("PASSWORD_RESET ");
                    break;
                case "LOCKED_OUT":  //user account is locked, unlock required
                    logger.Debug("LOCKED_OUT ");
                    break;
                case "MFA_ENROLL":   //user must select and enroll an available factor 
                    logger.Debug("MFA_ENROLL ");
                    break;
                case "MFA_ENROLL_ACTIVATE":   //user must activate the factor to complete enrollment
                    logger.Debug("MFA_ENROLL_ACTIVATE ");
                    break;
                case "MFA_REQUIRED":    //user must provide second factor with previously enrolled factor
                    logger.Debug("MFA_REQUIRED ");
                    break;

                case "MFA_CHALLENGE":      //use must verify factor specifc challenge
                    logger.Debug("MFA_CHALLENGE ");
                    break;

                case "SUCCESS":      //authentication is complete
                    logger.Debug("SUCCESS");
                    TempData["errMessage"] = "Authn Login Successful ";
                    TempData["oktaOrg"] = apiUrl;

                    string landingPage = null;
                    if (string.IsNullOrEmpty(relayState))
                    {
                        landingPage = location + "/AltLanding/UnprotectedLanding";
                    }
                    else
                    {
                        landingPage = relayState;
                    }

                    //optionaly get session Id locally
                    Session oktaSession = new Okta.Core.Models.Session();
                    oktaSession = oktaSessionMgmt.CreateSession(mySessionToken);
                    string cookieToken = oktaSession.CookieToken;
                    logger.Debug("session Id " + oktaSession.Id + " for User " + userName);
                    mySessionToken = cookieToken;

                    //exchange sessionToken for sessionCookie in OIDC Implicit workflow
                    Random random = new Random();
                    string nonceValue = random.Next(99999, 1000000).ToString();
                    string stateCode = "myStateInfo";
                    string oauthUrl = appSettings["oidc.authServer"] + "/v1/authorize?response_type=code&response_mode=query&client_id=" + appSettings["oidc.spintweb.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateCode + "&nonce=" + nonceValue + "&redirect_uri=" + appSettings["oidc.spintweb.RedirectUri"] + "&sessionToken=" + mySessionToken;
                    //string oauthUrl = appSettings["oidc.authServer"] + "/v1/authorize?response_type=code&response_mode=query&client_id=" + appSettings["oidc.spintweb.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateCode + "&nonce=" + nonceValue + "&redirect_uri=" + appSettings["oidc.spintweb.RedirectUri"] + "&sessionToken=" + mySessionToken + "&extra_param=myFavoriteData";
                    //string oauthUrl = appSettings["oidc.authServer"] + "/v1/authorize?response_type=code&idp=0oak4qcg796eVYakY0h7&response_mode=query&client_id=" + appSettings["oidc.spintweb.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateCode + "&nonce=" + nonceValue + "&redirect_uri=" + appSettings["oidc.spintweb.RedirectUri"];

                    return Redirect(oauthUrl);


 

                 //break;
                default:
                    logger.Debug("Status: " + myStatus);
                    TempData["errMessage"] = "Status: " + myStatus;
                    break;
            }//end of switch
            TempData["userName"] = userName;

            return RedirectToAction("UnprotectedLanding", "AltLanding");
        }

        [HttpPost]
        public ActionResult PkceRoute()
        {
            string userName = Request["userName"];
            string passWord = Request["passWord"];
            string authnlogin_but = Request["authnlogin_but"];
            string oidclogin_but = Request["oidclogin_but"];
            string oidc_but = Request["oidc_but"];
            string location = Request["location"];
            string myStatus = null;
            string myStateToken;
            string mySessionToken;
            string myOktaId = null;
            AuthResponse userAuthClientRsp;

            // set relayState 
            string relayState = Request["relayState"];
            TempData["relayState"] = relayState;

            Uri orgUri = new Uri(apiUrl);
            _orgSettings = new OktaSettings();
            _orgSettings.ApiToken = apiToken;
            _orgSettings.BaseUri = orgUri;

            _oktaClient = new OktaClient(_orgSettings);
            _usersClient = new UsersClient(_orgSettings);
            _authClient = new AuthClient(_orgSettings);
            try
            {

                userAuthClientRsp = _authClient.Authenticate(username: userName, password: passWord, relayState: relayState);
                logger.Debug("thisAuth status " + userAuthClientRsp.Status);
                myStatus = userAuthClientRsp.Status;
                myStateToken = userAuthClientRsp.StateToken;
                mySessionToken = userAuthClientRsp.SessionToken;
                if (userAuthClientRsp.Embedded.User != null)
                {
                    myOktaId = userAuthClientRsp.Embedded.User.Id;
                }

            }
            catch (OktaException ex)
            {
                if (ex.ErrorCode == "E0000004")
                {
                    logger.Debug("Invalid Credentials for User: " + userName);
                    TempData["errMessage"] = "Invalid Credentials for User: " + userName;
                }
                else if (ex.ErrorCode == "E0000085")
                {
                    logger.Debug("Access Denied by Polciy for User: " + userName);
                    //   TempData["errMessage"] = "Access Denied by Polciy for User: " + userName;
                    TempData["errMessage"] = "Access Denied by Polciy for User: " + userName;
                }
                else
                {
                    logger.Error(userName + " = " + ex.ErrorCode + ":" + ex.ErrorSummary);
                    // generic failure
                    TempData["errMessage"] = "Sign in process failed!";
                }
                TempData["userName"] = userName;
                return RedirectToAction("Login");
            }

            switch (myStatus)
            {

                case "PASSWORD_WARN":  //password about to expire
                    logger.Debug("PASSWORD_WARN ");
                    break;
                case "PASSWORD_EXPIRED":  //password has expired
                    logger.Debug("PASSWORD_EXPIRED ");
                    break;

                case "RECOVERY":  //user has requested a recovery token
                    logger.Debug("RECOVERY ");
                    break;
                case "RECOVERY_CHALLENGE":  //user must verify factor specific recovery challenge
                    logger.Debug("RECOVERY_CHALLENGE ");
                    break;
                case "PASSWORD_RESET":     //user satified recovery and must now set password
                    logger.Debug("PASSWORD_RESET ");
                    break;
                case "LOCKED_OUT":  //user account is locked, unlock required
                    logger.Debug("LOCKED_OUT ");
                    break;
                case "MFA_ENROLL":   //user must select and enroll an available factor 
                    logger.Debug("MFA_ENROLL ");
                    break;
                case "MFA_ENROLL_ACTIVATE":   //user must activate the factor to complete enrollment
                    logger.Debug("MFA_ENROLL_ACTIVATE ");
                    break;
                case "MFA_REQUIRED":    //user must provide second factor with previously enrolled factor
                    logger.Debug("MFA_REQUIRED ");
                    break;

                case "MFA_CHALLENGE":      //use must verify factor specifc challenge
                    logger.Debug("MFA_CHALLENGE ");
                    break;

                case "SUCCESS":      //authentication is complete
                    logger.Debug("SUCCESS");
                    TempData["errMessage"] = "Authn Login Successful ";
                    TempData["oktaOrg"] = apiUrl;

                    string landingPage = null;
                    if (string.IsNullOrEmpty(relayState))
                    {
                        landingPage = location + "/AltLanding/UnprotectedLanding";
                    }
                    else
                    {
                        landingPage = relayState;
                    }

                    //optionaly get session Id locally
                    Session oktaSession = new Okta.Core.Models.Session();
                    oktaSession = oktaSessionMgmt.CreateSession(mySessionToken);
                    string cookieToken = oktaSession.CookieToken;
                    logger.Debug("session Id " + oktaSession.Id + " for User " + userName);
                    mySessionToken = cookieToken;

                    //exchange sessionToken for sessionCookie in OIDC Implicit workflow
                    Random random = new Random();
                    string nonceValue = random.Next(99999, 1000000).ToString();
                    string stateCode = "myStateInfo";
                    string codeVerifier = oktaOidcHelper.CreateCodeVerifier();
                    //store codeVerifier for token endpoint
                    cacheService.SavePasscode("myKey", codeVerifier);
                    string codeChallenge = oktaOidcHelper.CreateCodeChallenge(codeVerifier);
                    string oauthUrl = appSettings["oidc.authServer"] + "/v1/authorize?response_type=code&response_mode=query&code_challenge_method=S256&code_challenge=" + codeChallenge + "&client_id=" + appSettings["oidc.spintnative.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateCode + "&nonce=" + nonceValue + "&redirect_uri=" + appSettings["oidc.spintnative.RedirectUri_PKCE"] + "&sessionToken=" + mySessionToken + "&extra_param=myFavoriteData";
                    return Redirect(oauthUrl);




                //break;
                default:
                    logger.Debug("Status: " + myStatus);
                    TempData["errMessage"] = "Status: " + myStatus;
                    break;
            }//end of switch
            TempData["userName"] = userName;

            return RedirectToAction("UnprotectedLanding", "AltLanding");
        }


    }
}