using log4net;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OIDC_CustomLogin.Models;
using Okta.Core.Models;
using OIDC_CustomLogin.Services;
using Okta.Core.Clients;
using System.Net.Http;
using Okta.Core;

namespace OIDC_CustomLogin.Controllers
{
    public class AltLandingController : Controller
    {
        ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        // ILog logger = LogManager.GetLogger("SpecialLogFile");

        NameValueCollection appSettings = ConfigurationManager.AppSettings;
        // Org settings for primary Org
        private static string apiUrl = ConfigurationManager.AppSettings["okta.apiUrl"];
        private static string apiToken = ConfigurationManager.AppSettings["okta.apiToken"];

        private OktaOidcHelper oktaOidcHelper = new OktaOidcHelper(apiUrl, apiToken);
        private OktaAPIHelper oktaApiHelper = new OktaAPIHelper(apiUrl, apiToken);
        //private OktaClient _oktaClient;
        //private OktaSettings _orgSettings;




        //[HttpGet]
        //public ActionResult AltLanding()
        //{
        //    GetInfoResponse getInfoResponse = new GetInfoResponse();
        //    TempData["oktaOrg"] = MvcApplication.apiUrl;
        //    //TempData["token"] = MvcApplication.apiToken;
        //    return View(getInfoResponse);
        //}



        [HttpGet]
        public ActionResult UnprotectedLanding()
        {
            logger.Debug("Get UnprotectedLanding");
            GetInfoResponse getInfoResponse = new GetInfoResponse();
            TempData["oktaOrg"] = apiUrl;
 
            return View(getInfoResponse);
        }

        [HttpPost]
        public ActionResult AuthCodeLanding(string relayState)
        {
            logger.Debug("Post AuthCodeLanding");
            GetInfoResponse rspData = new GetInfoResponse();
            TempData["oktaOrg"] = apiUrl;
            return View("AuthCodeLanding", rspData);
        }

        [HttpGet]
        public ActionResult AuthCodeLanding()
        {
            logger.Debug("Get AuthCodeLanding");
            GetInfoResponse getInfoResponse = new GetInfoResponse();
            TempData["oktaOrg"] = apiUrl;

            return View(getInfoResponse);
        }

        [HttpPost]
        public ActionResult ImplicitLanding(string idToken,string accessToken)
        {
            logger.Debug("Post ImplicitLanding");
            // GetInfoResponse getInfoResponse = new GetInfoResponse();
            OidcIdTokenMin oidcIdToken = new OidcIdTokenMin();
            System.Security.Claims.ClaimsPrincipal jsonPayload = null;
            System.IdentityModel.Tokens.Jwt.JwtSecurityToken tokenReceived = null;

            //string clientId = appSettings["oidc.spintweb.clientId"];
            string issuer = appSettings["oidc.issuer"];
            string audience = appSettings["oidc.spintweb.clientId"];

            jsonPayload = oktaOidcHelper.ValidateIdToken(idToken, issuer, audience);
            if (jsonPayload != null &&  jsonPayload.Identity.IsAuthenticated)
            {
                TempData["errMessage"] = "Id Token Validated";
                tokenReceived = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(idToken);
            }
            else
            {
                TempData["errMessage"] = "Invalid ID Token!";

            }
            TempData["idToken"] = idToken;
            TempData["accessToken"] = accessToken;
            TempData["oktaOrg"] = apiUrl;

            return View("ImplicitLanding", oidcIdToken);
        }

        [HttpGet]
        public ActionResult ImplicitLanding()
        {
            logger.Debug("Get ImplicitLanding");
            OidcIdTokenMin oidcIdToken = new OidcIdTokenMin();
            TempData["oktaOrg"] = apiUrl;
            return View("ImplicitLanding", oidcIdToken);
        }

        [HttpGet]
        public ActionResult ResOwnerLanding()
        {
            logger.Debug("Get ResOwnerLanding");
            OidcIdTokenMin oidcIdToken = new OidcIdTokenMin();
            TempData["oktaOrg"] = apiUrl;
            return View("ResOwnerLanding", oidcIdToken);
        }

        [HttpGet]
        public ActionResult ClientCredLanding()
        {
            logger.Debug("get ClientCredLanding");
            TempData["oktaOrg"] = apiUrl;
            return View("ClientCredLanding");
        }

        //[HttpGet]
        //public ActionResult WebApi()
        //{
        //    logger.Debug("WebApi");

        //    return View();
        //}

        //this is hit when token is refreshed
        [HttpGet]
        public ActionResult InitiateSendWebApi_wToken()
        {
            logger.Debug("Get InitiateSendWebApi_wToken");
            string accessToken = TempData["accessToken"].ToString();
            string refreshToken = TempData["refreshToken"].ToString();

            TempData["oktaOrg"] = apiUrl;
            TempData["accessToken"] = accessToken;
            TempData["refreshToken"] = refreshToken;

            string destPage = appSettings["oidc.webApiAprotected"];

            bool rspSendApiA = oktaOidcHelper.SendTokenToWebApi(accessToken,  destPage);

            if (rspSendApiA)
            {
                logger.Debug("Send to Web Api Successful");
                TempData["errMessage"] = "Send to Web Api Successful";
                return View("../AltLanding/WebApiReturn");
            }
            else
            {
                logger.Debug("Send to Web Api Failed");
                TempData["errMessage"] = "Send to Web Api Failed";
                return RedirectToAction("RenewAccessToken", "Oidc");
            }

        }

        [HttpPost]
        public ActionResult SendWebApi_wToken()
        {
            logger.Debug("Post SendWebApi_wToken");
            string accessToken = Request["accessToken"];
            string refreshToken = Request["refreshToken"];

            TempData["oktaOrg"] = apiUrl;
            TempData["accessToken"] = accessToken;
            TempData["refreshToken"] = refreshToken;

            string destPage = appSettings["oidc.webApiAprotected"];

            bool rspSendApiA = oktaOidcHelper.SendTokenToWebApi(accessToken, destPage);

            if (rspSendApiA)
            {
                logger.Debug("Send to Web Api Successful");
                TempData["errMessage"] = "Send to Web Api Successful";
                return View("../AltLanding/WebApiReturn");
            }
            else
            {
                logger.Debug("Send to Web Api Failed");
                TempData["errMessage"] = "Send to Web Api Failed";
                return RedirectToAction("RenewAccessToken", "Oidc");
            }
            
        }


        [HttpPost]
        public ActionResult SendWebApi_afterSetCookie()
        {
            logger.Debug("Post SendWebApi_afterSetCookie");

            TempData["oktaOrg"] = apiUrl;

            string destPage = appSettings["oidc.webApiAprotected"];

            bool rspSendApiA = oktaApiHelper.SendRequestToWebApi_NoToken(destPage);

            if (rspSendApiA)
            {
                logger.Debug("Send to Web Api Successful");
                TempData["errMessage"] = "Send to Web Api Successful";
            }
            else
            {
                logger.Debug("Send to Web Api Failed");
                TempData["errMessage"] = "Send to Web Api Failed";
            }

            return View("../AltLanding/WebApiReturn");
        }

        [HttpPost]
        public ActionResult GetUserInfo()
        {
            logger.Debug("Home GetUserInfo");

            string idToken = Request["idToken"];
            string accessToken = Request["accessToken"];
            string refreshToken = Request["refreshToken"];
            string userinfo_but = Request["userinfo_but"];
            string introspection_but = Request["introspection_but"];
            string sendToken_but = Request["sendToken_but"];
            string userinfo2_but = Request["userinfo2_but"];
            string introspection2_but = Request["introspection2_but"];
            string sendToken2_but = Request["sendToken2_but"];
            string oidc_but = Request["oidc_but"];
            string session_id = Request["session_id"];
            string revoke_but = Request["revoke_but"];
            string revoke2_but = Request["revoke2_but"];
            string location = Request["location"];
            
            string error = null;
            string error_description = null;
            string token_type = null;
            string scope = null;
            string active = null;
            IRestResponse<GetInfoResponse> getInfoRsp = null;
            GetInfoResponse rspData = new GetInfoResponse();


            if (userinfo_but == "Get UserInfo" || userinfo2_but == "Get UserInfo")
            {
                if (!string.IsNullOrEmpty(accessToken))
                {
                    var client = new RestClient(appSettings["oidc.authServer"] + "/v1/userinfo");
                    var request = new RestRequest(Method.GET);
                    // request.AddHeader("cache-control", "no-cache");
                    request.AddHeader("Accept", "application/json");
                    request.AddHeader("Authorization", " Bearer " + accessToken);
                    getInfoRsp = client.Execute<GetInfoResponse>(request);
                    if (getInfoRsp.Data != null)
                    {
                        error = getInfoRsp.Data.error;
                        error_description = getInfoRsp.Data.error_description;
                    }
                    if (getInfoRsp.Data != null)
                    {
                        rspData = getInfoRsp.Data;
                    }

                    if (error != null)
                    {
                        TempData["errMessage"] = "Get UserInfo error " + error_description;
                    }
                    else
                    {
                        if (getInfoRsp.StatusDescription != "OK")
                        {
                            TempData["errMessage"] = "Get UserInfo Bad Request ";
                        }
                        else
                        {
                            TempData["errMessage"] = "Get UserInfo SUCCESS email = " + getInfoRsp.Data.email;
                        }
                    }
                }
                else
                {
                    TempData["errMessage"] = "Get UserInfo error; access_token NOT present";
                }
            }


            if (introspection_but == "Token Introspection" || introspection2_but == "Token Introspection")
            {
                logger.Debug("Token Introspection");
                var client = new RestClient(appSettings["oidc.authServer"] + "/v1/introspect");

                IRestResponse<IntrospectionResponse> introspectRsp = null;
                string basicAuth = appSettings["oidc.spintweb.clientId"] + ":" + appSettings["oidc.spintweb.clientSecret"];

                var bytesBasicAuth = System.Text.Encoding.UTF8.GetBytes(basicAuth);
                string encodedBasicAuth = System.Convert.ToBase64String(bytesBasicAuth);

                if (!string.IsNullOrEmpty(accessToken))
                {
                    //access_token_status = "access_token present";

                    var request = new RestRequest(Method.POST);
                    // request.AddHeader("cache-control", "no-cache");
                    request.AddHeader("Accept", "application/json");
                    request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                    request.AddHeader("Authorization", " Basic " + encodedBasicAuth);
                    request.AddQueryParameter("token", accessToken);
                    request.AddQueryParameter("token_type_hint", "access_token");
                    //request.AddQueryParameter("token", idToken);
                    //request.AddQueryParameter("token_type_hint", "id_token");

                    introspectRsp = client.Execute<IntrospectionResponse>(request);
                    if (introspectRsp.Data != null)
                    {
                        error = introspectRsp.Data.error;
                        error_description = introspectRsp.Data.error_description;
                        token_type = introspectRsp.Data.token_type;
                        scope = introspectRsp.Data.scope;
                        active = introspectRsp.Data.active;
                    }

                    if (introspectRsp.StatusDescription != "OK")
                    {
                        TempData["errMessage"] = "Token Introspection Bad Request ";
                    }
                    else
                    {
                        if (error != null)
                        {
                            TempData["errMessage"] = "Token Introspection error " + error_description;
                        }
                        else
                        {
                            TempData["errMessage"] = "Token Introspection SUCCESS token_type = " + token_type + " scope = " + scope + " is_active " + active;
                        }
                    }

                }
                else
                {
                    TempData["errMessage"] = "Token Introspection; access_token NOT present";
                }

            }

            if (revoke_but == "Token Revoke" || revoke2_but == "Token Revoke")
            {
                logger.Debug("Token Revoke");
                var client = new RestClient(appSettings["oidc.authServer"] + "/v1/revoke");


                IRestResponse revokeRsp = null;
                string basicAuth = appSettings["oidc.spintweb.clientId"] + ":" + appSettings["oidc.spintweb.clientSecret"];

                var bytesBasicAuth = System.Text.Encoding.UTF8.GetBytes(basicAuth);
                string encodedBasicAuth = System.Convert.ToBase64String(bytesBasicAuth);

                if (!string.IsNullOrEmpty(accessToken))
                {
                    //access_token_status = "access_token present";

                    var request = new RestRequest(Method.POST);
                    // request.AddHeader("cache-control", "no-cache");
                    request.AddHeader("Accept", "application/json");
                    request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                    request.AddHeader("Authorization", " Basic " + encodedBasicAuth);
                    request.AddQueryParameter("token", accessToken);
                    request.AddQueryParameter("token_type_hint", "access_token");
                    //request.AddQueryParameter("token", idToken);
                    //request.AddQueryParameter("token_type_hint", "id");
                    revokeRsp = client.Execute(request);

                    if (revokeRsp.StatusDescription != "OK")
                    {
                        TempData["errMessage"] = "Token Revoke Bad Request ";
                    }
                    else
                    {
                        if (error != null)
                        {
                            TempData["errMessage"] = "Token Revoke error " + error_description;
                        }
                        else
                        {
                            TempData["errMessage"] = "Token Revoke SUCCESS " ;
                        }
                    }
                }
                else
                {
                    TempData["errMessage"] = "Token Revoke; access_token NOT present";
                }
            }

  

            if (oidc_but == "Initiate Auth OIDC")
            {
                //version using Custom Authorization Server
                logger.Debug("Initiate OIDC Auth Code with Session");
                Random random = new Random();
                string nonceValue = random.Next(99999, 1000000).ToString();
                string stateValue = "myStateInfo";
                string oauthUrl = appSettings["oidc.authServer"] + "/v1/authorize?response_type=code&response_mode=query&client_id=" + appSettings["oidc.spintweb.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateValue + "&nonce=" + nonceValue + "&redirect_uri=" + appSettings["oidc.spintweb.RedirectUri"];
                return Redirect(oauthUrl);
            }

            if (oidc_but == "Initiate Implicit OIDC")
            {
                //version using Custom  Authorization Server
                logger.Debug("Initiate OIDC Implicit with Session");
                Random random = new Random();
                string nonceValue = random.Next(99999, 1000000).ToString();
                string stateValue = "myStateInfo";
                string oauthUrl = appSettings["oidc.authServer"] + "/v1/authorize?response_type=id_token&response_mode=form_post&client_id=" + appSettings["oidc.spintnative.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateValue + "&nonce=" + nonceValue + "&redirect_uri=" + appSettings["oidc.spintnative.RedirectUri"];
                return Redirect(oauthUrl);
            }



            TempData["accessToken"] = accessToken;
            TempData["oktaOrg"] = appSettings["okta.apiUrl"];
            return View("AuthCodeLanding", rspData);
        }


    }
}