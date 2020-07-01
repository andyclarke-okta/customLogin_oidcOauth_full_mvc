using log4net;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Configuration;

using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using OIDC_CustomLogin.Models;
using OIDC_CustomLogin.Services;
using System.Web.Routing;
//using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace OIDC_CustomLogin.Controllers
{
    public class OidcController : Controller
    {
        ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);


        NameValueCollection appSettings = ConfigurationManager.AppSettings;

        // Org settings for Okta Org
        private static string apiUrl = ConfigurationManager.AppSettings["okta.apiUrl"];
        private static string apiToken = ConfigurationManager.AppSettings["okta.apiToken"];
        private OktaOidcHelper oktaOidcHelper = new OktaOidcHelper(apiUrl, apiToken);

        private CacheService cacheService = new CacheService();


        [HttpGet]
        public ActionResult InitiateService()
        {
            //Default endoint for Custom Authorization Server
            logger.Debug("Get OIDC Endpoint_Service");
            return RedirectToAction("UnprotectedLanding", "AltLanding");
        }


        [HttpGet]
        public ActionResult ValidationEndpoint(string code, string state)
        {
            //use this for auth code workflow
            logger.Debug("Get OIDC for auth code workflow");


            logger.Debug(" code = " + code + " state " + state);

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
            OidcIdToken oidcIdToken = new OidcIdToken();
            OidcAccessToken oidcAccessToken = new OidcAccessToken();
            string basicAuth = appSettings["oidc.spintweb.clientId"] + ":" + appSettings["oidc.spintweb.clientSecret"];

            var bytesBasicAuth = System.Text.Encoding.UTF8.GetBytes(basicAuth);
            string encodedBasicAuth = System.Convert.ToBase64String(bytesBasicAuth);


            try
            {
                //var client = new RestClient(MvcApplication.apiUrl + "/oauth2/v1/token");
                var client = new RestClient(appSettings["oidc.authServer"] + "/v1/token");
                var request = new RestRequest(Method.POST);
                request.AddHeader("Accept", "application/json");
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddHeader("Authorization", " Basic " + encodedBasicAuth);
                request.AddQueryParameter("grant_type", "authorization_code");
                request.AddQueryParameter("code", code);
                request.AddQueryParameter("redirect_uri", appSettings["oidc.spintweb.RedirectUri"]);
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
                    id_token_status = "id_token present";
                    idToken = response.Data.id_token;

                    string issuer = appSettings["oidc.issuer"];
                    string audience = appSettings["oidc.spintweb.clientId"];
                    //jsonPayload = oktaOidcHelper.DecodeAndValidateIdToken(idToken, clientId, issuer, audience);
                    jsonPayload = oktaOidcHelper.ValidateIdToken(idToken, issuer, audience);
                    if (jsonPayload.Identity.IsAuthenticated)
                    {
                        TempData["errMessage"] = jsonPayload.ToString();
                        //System.IdentityModel.Tokens.Jwt.JwtSecurityToken tokenReceived = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(idToken);
                        //oidcIdToken = Newtonsoft.Json.JsonConvert.DeserializeObject<OidcIdToken>(idToken);
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
                }
                else
                {
                    access_token_status = "access_token NOT present";
                }

                if (response.Data.refresh_token != null)
                {
                    refreshToken = response.Data.refresh_token;
                    refresh_token_status = "refresh_token present";
                    TempData["refreshToken"] = response.Data.refresh_token;
                    
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

            if (error != null)
            {

                TempData["errMessage"] = "Error " + error_description;
                TempData["oktaOrg"] = apiUrl;
                return RedirectToAction("UnprotectedLanding", "AltLanding");
            }
            else
            {

                TempData["errMessage"] = "SUCCESS token_type = " + token_type + " scope = " + scope + " : " + id_token_status + " : " + access_token_status + " oktaId = " + oidcIdToken.sub;
                TempData["oktaOrg"] = apiUrl;
                return RedirectToAction("AuthCodeLanding", "AltLanding");

            }

        }


        [HttpPost]
        public ActionResult ValidationEndpoint()
        {
            //use this for implicit workflow
            logger.Debug("Post OIDC for implicit workflow");


            string myState = Request["state"];
            string idToken = Request["id_token"];
            string accessToken = Request["access_token"];
            string tokenType = Request["token_type"];
            string expires = Request["expires_in"];
            string scope = Request["scope"];

            System.Security.Claims.ClaimsPrincipal jsonPayload = null;
            string accessTokenStatus = null;
            string idTokenStatus = null;

            OidcIdToken oidcIdToken = new OidcIdToken();
            OidcIdTokenMin oidcIdTokeMin = new OidcIdTokenMin();

            if (idToken != null)
            {
                idTokenStatus = " ID Token Present";
                TempData["idToken"] = idToken;
                //string clientId = appSettings["oidc.spintnative.clientId"];
                string issuer = appSettings["oidc.issuer"];
                string audience = appSettings["oidc.spintweb.clientId"];
                //jsonPayload = oktaOidcHelper.DecodeAndValidateIdToken(idToken, clientId, issuer, audience);
                jsonPayload = oktaOidcHelper.ValidateIdToken(idToken, issuer, audience);
                if (jsonPayload.Identity.IsAuthenticated)
                {
                    TempData["errMessage"] = jsonPayload.ToString();
                    System.IdentityModel.Tokens.Jwt.JwtSecurityToken tokenReceived = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(idToken);
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
                idTokenStatus = " ID Token Not Found";
            }

            if (accessToken != null)
            {
                accessTokenStatus = "access_token Present";
                TempData["accessToken"] = accessToken;

            }
            else
            {
                accessTokenStatus = "access_token NOT Found";
            }


            if (accessToken != null || idToken != null)
            {
                TempData["errMessage"] = "SUCCESS token_type = " + tokenType + " expires = " + expires + " scope = " + scope + " : " + idTokenStatus + " : " + accessTokenStatus + " oktaId = " + oidcIdToken.sub;
                TempData["oktaOrg"] = apiUrl;

                return View("../AltLanding/ImplicitLanding", oidcIdTokeMin);
            }
            else
            {
                TempData["errMessage"] = "Error token_type = " + tokenType + " expires = " + expires + " scope = " + scope + " : " + idTokenStatus + " : " + accessTokenStatus + " oktaId = " + oidcIdToken.sub;
                TempData["oktaOrg"] = apiUrl;
                return View("../AltLanding/UnprotectedLanding");
            }


        }



        [HttpGet]
        public ActionResult Endpoint_PKCE(string code, string state)
        {
            //use this for auth code with PKCE workflow
            logger.Debug("Get OIDC Endpoint_Code");

            logger.Debug(" code = " + code + " state " + state);

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

            OidcAccessToken oidcAccessToken = new OidcAccessToken();
            string codeVerifier = cacheService.GetPasscode("myKey");

            try
            {
                var client = new RestClient(appSettings["oidc.authServer"] + "/oauth2/v1/token");
                var request = new RestRequest(Method.POST);
                request.AddHeader("Accept", "application/json");
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddQueryParameter("grant_type", "authorization_code");
                request.AddQueryParameter("code", code);
                request.AddQueryParameter("code_verifier", codeVerifier);
                request.AddQueryParameter("redirect_uri", appSettings["oidc.spintnative.RedirectUri_PKCE"]);
                request.AddQueryParameter("client_id", appSettings["oidc.spintnative.clientId"]);
                response = client.Execute<TokenRequestResponse>(request);
                error = response.Data.error;
                error_description = response.Data.error_description;
                token_type = response.Data.token_type;
                scope = response.Data.scope;

                if (response.Data.id_token != null)
                {
                    id_token_status = "id_token present";
                    idToken = response.Data.id_token;
                    string issuer = appSettings["oidc.issuer"];
                    string audience = appSettings["oidc.spintweb.clientId"];
                    jsonPayload = oktaOidcHelper.ValidateIdToken(idToken, issuer, audience);
                    if (jsonPayload.Identity.IsAuthenticated)
                    {
                        TempData["errMessage"] = jsonPayload.ToString();
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
                    TempData["accessToken"] = accessToken;
                }
                else
                {
                    access_token_status = "access_token NOT present";
                }

                if (response.Data.refresh_token != null)
                {
                    refreshToken = response.Data.refresh_token;
                    refresh_token_status = "refresh_token present";
                    TempData["refreshToken"] = refreshToken;
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

            if (error != null)
            {
                TempData["errMessage"] = "OIDC_Get Oauth Endpoint_Web error " + error_description;
                TempData["oktaOrg"] = apiUrl;
                return RedirectToAction("UnprotectedLanding", "AltLanding");
            }
            else
            {

                TempData["errMessage"] = "OIDC_Get Oauth Endpoint_Web SUCCESS = " + id_token_status + " : " + access_token_status;
                TempData["oktaOrg"] = apiUrl;
                return RedirectToAction("AuthCodeLanding", "AltLanding");
            }
        }

        [HttpGet]
        public ActionResult RenewAccessToken()
        {
            //string idToken = TempData["idToken"].ToString();
            string accessToken = TempData["accessToken"].ToString();
            string refreshToken = TempData["refreshToken"].ToString();
            //logger.Debug(" code = " + code + " state " + state);
            TempData["accessToken"] = accessToken;
            //TempData["idToken"] = idToken;
            TempData["refreshToken"] = refreshToken;
            string error = null;
            string error_description = null;
            string token_type = null;
            string scope = null;
            string id_token_status = null;
 
            string access_token_status = null;
 
            string refresh_token_status = null;

            System.Security.Claims.ClaimsPrincipal jsonPayload = null;
            IRestResponse<TokenRequestResponse> response = null;
            string basicAuth = appSettings["oidc.spintweb.clientId"] + ":" + appSettings["oidc.spintweb.clientSecret"];

            var bytesBasicAuth = System.Text.Encoding.UTF8.GetBytes(basicAuth);
            string encodedBasicAuth = System.Convert.ToBase64String(bytesBasicAuth);


            try
            {
                //var client = new RestClient(MvcApplication.apiUrl + "/oauth2/v1/token");
                var client = new RestClient(appSettings["oidc.authServer"] + "/v1/token");
                var request = new RestRequest(Method.POST);
                // request.AddHeader("cache-control", "no-cache");
                request.AddHeader("Accept", "application/json");
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddHeader("Authorization", " Basic " + encodedBasicAuth);
                request.AddQueryParameter("grant_type", "refresh_token");
                request.AddQueryParameter("refresh_token", refreshToken);
                request.AddQueryParameter("redirect_uri", appSettings["oidc.spintweb.RedirectUri"]);
                response = client.Execute<TokenRequestResponse>(request);
                if (response.Data != null)
                {
                    error = response.Data.error;
                    error_description = response.Data.error_description;
                    token_type = response.Data.token_type;
                    scope = response.Data.scope;
                }

                if (response.Data.access_token != null)
                {
                    accessToken = response.Data.access_token;
                    TempData["accessToken"] = accessToken;
                    string clientId = appSettings["oidc.spintweb.clientId"];
                    string issuer = appSettings["oidc.issuer"];
                    //string audience = appSettings["oidc.customAuthServer.RedirectUri"];
                    string audience = appSettings["oidc.spintweb.RedirectUri"];
                    //jsonPayload = oktaOidcHelper.DecodeAndValidateIdToken(accessToken, clientId, issuer, audience);
                    jsonPayload = oktaOidcHelper.ValidateIdToken(accessToken, issuer, audience);
                }
                else
                {
                    access_token_status = "access_token NOT present";
                }

                if (response.Data.refresh_token != null)
                {
                    refreshToken = response.Data.refresh_token;
                    refresh_token_status = "refresh_token present";
                    TempData["refreshToken"] = refreshToken;
                }
                else
                {
                    refresh_token_status = "refresh_token NOT present";
                }
            }
            catch (Exception ex)
            {

                //logger.Error(ex.ToString());
            }

            if (accessToken != null)
            {

                return RedirectToAction("InitiateSendWebApi_wToken", "AltLanding");
            }
            else
            {
                logger.Debug(error + " : " + error_description);
                TempData["errMessage"] = error + " : " + error_description;
                return View("../AltLanding/WebApiA");
            }

        }


    }
}