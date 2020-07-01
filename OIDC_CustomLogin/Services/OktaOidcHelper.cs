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
using System.Security.Cryptography;
using RestSharp;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Net.Http;
using Newtonsoft.Json;
using System.Text;

using Newtonsoft.Json.Linq;

using System.Collections;
using System.Diagnostics;

using System.Web.Mvc;

using System.Collections.Specialized;

using System.Threading.Tasks;
using System.Threading;

using System.IO;
using System.Web.UI;
using OIDC_CustomLogin.Models;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;


namespace OIDC_CustomLogin.Services
{
    public class OktaOidcHelper
    {
        private OktaSettings _orgSettings;
        private string _apiToken;
        private string _apiUrl;

        private UsersClient _usersClient;
        private OktaClient _oktaClient;
        NameValueCollection appSettings = ConfigurationManager.AppSettings;
        private static ILog _logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        public OktaOidcHelper(string apiUrl, string apiToken)
        {
            _apiUrl = apiUrl;
            Uri orgUri = new Uri(apiUrl);
            _orgSettings = new OktaSettings();
            _orgSettings.ApiToken = apiToken;
            _orgSettings.BaseUri = orgUri;

            _oktaClient = new OktaClient(_orgSettings);
            _usersClient = new UsersClient(_orgSettings);

        }

        public string CreateCodeVerifier()
        {
            string verifier = null;

            var generator = RandomNumberGenerator.Create();
            var bytes = new byte[32];
            generator.GetBytes(bytes);
            //verifier = Convert.ToBase64String(bytes);
            verifier = HttpServerUtility.UrlTokenEncode(bytes);
            //verifier = "M25iVXpKU3puUjFaYWg3T1NDTDQtcW1ROUY5YXlwalNoc0hhakxifmZHag";

            int myCount = verifier.Length;
            return verifier;
        }

        public string CreateCodeChallenge(string codeVerifier)
        {
            string challenge = null;

            HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider();
            var byteValue = System.Text.Encoding.UTF8.GetBytes(codeVerifier);
            var byteHash = hashAlgorithm.ComputeHash(byteValue);
            challenge = Convert.ToBase64String(byteHash);
            challenge = challenge.Replace("/", "_").Replace("+", "-").Replace("=", "");

            //challenge = "qjrzSW9gMiUgpUvqgEPE4_-8swvyCtfOVvg55o5S_es";

            return challenge;
        }


        public System.Security.Claims.ClaimsPrincipal ValidateIdToken(string idToken, string issuer, string audience)
        {
            System.Security.Claims.ClaimsPrincipal claimPrincipal = null;

            IConfigurationManager<OpenIdConnectConfiguration> configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{issuer}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
            //IConfigurationManager<OpenIdConnectConfiguration> configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{issuer}/.well-known/oauth-authorization-server", new OpenIdConnectConfigurationRetriever());

            OpenIdConnectConfiguration openIdConfig = AsyncHelper.RunSync(async () => await configurationManager.GetConfigurationAsync(CancellationToken.None));

            TokenValidationParameters validationParameters =
                new TokenValidationParameters
                {
                    ValidAudience = audience,
                    ValidIssuer = issuer,
                    IssuerSigningKeys = openIdConfig.SigningKeys,
                    ValidateIssuerSigningKey = true,
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateLifetime = true
                };

            Microsoft.IdentityModel.Tokens.SecurityToken validatedToken;
            System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();

            try
            {
                claimPrincipal = handler.ValidateToken(idToken, validationParameters, out validatedToken);
            }
            catch (Exception ex)
            {
                var error = ex.Message;
            }

            return claimPrincipal;
        }


        //this method is depreciated but still valid
        //public string DecodeAndValidateIdToken(string idToken, string clientId, string issuer, string audience)
        //{
        //    ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        //    logger.Debug("DecodeAndValidateIdToken");
        //    OidcGetKeys oidcGetKeys = new OidcGetKeys();
        //    oidcGetKeys.keys = new List<Key>();
        //    IRestResponse<OidcGetKeys> response = null;
        //    //var clientId = appSettings["oidc.spintnative.clientId"];
        //    string secretKeyn = null;
        //    string secretKeye = null;
        //    string jsonPayload = null;

        //    //find key reference in JWT
        //    string[] parts = idToken.Split('.');
        //    string header = parts[0];
        //    string payload = parts[1];
        //    byte[] crypto = Base64UrlDecode(parts[2]);
        //    System.IdentityModel.Tokens.SecurityToken validatedToken;


        //    //decode JWT header and payload
        //    JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
        //    //SecurityToken tokenReceived = tokenHandler.ReadToken(idToken);
        //    JwtSecurityToken tokenReceived2 = new JwtSecurityToken(idToken);

        //    //decode JWT payload
        //    string decodePayload = Encoding.UTF8.GetString(Base64UrlDecode(payload));
        //    JObject payloadData = JObject.Parse(decodePayload);

        //    //decode JWT header
        //    string decodeHeader = Encoding.UTF8.GetString(Base64UrlDecode(header));
        //    JObject headerData = JObject.Parse(decodeHeader);
        //    //deserialize header to find key id of id token
        //    OidcHeader oidcHeader = new OidcHeader();
        //    oidcHeader = Newtonsoft.Json.JsonConvert.DeserializeObject<OidcHeader>(decodeHeader);
        //    //computer hash from JWT header and payload
        //    SHA256 sha256 = SHA256.Create();
        //    byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(header + '.' + payload));

        //    try
        //    {
        //        //get keys from okta
        //        var client = new RestClient(appSettings["oidc.authServer"] + "/v1/keys");

        //        var request = new RestRequest(Method.GET);
        //        // request.AddHeader("cache-control", "no-cache");
        //        request.AddHeader("Accept", "application/json");
        //        request.AddHeader("Content-Type", "application/json");
        //        request.AddQueryParameter("client_id", clientId);
        //        response = client.Execute<OidcGetKeys>(request);
        //        //loop through returned keys, copy match on kid
        //        foreach (var item in response.Data.keys)
        //        {
        //            if (oidcHeader.kid == item.kid)
        //            {
        //                secretKeyn = item.n;
        //                secretKeye = item.e;
        //            }
        //        }
        //    }
        //    catch (Exception)
        //    {
        //        logger.Error("falied to access keys from Authorization Server");
        //        return "Failed calling keys endpoint";
        //    }

        //    try
        //    {
        //        //incorporate public received from keys endpoint
        //        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        //        rsa.ImportParameters(
        //          new RSAParameters()
        //          {
        //              Modulus = FromBase64Url(secretKeyn),
        //              Exponent = FromBase64Url(secretKeye)
        //          });

        //        //verify JWT signature versus computed
        //        RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
        //        rsaDeformatter.SetHashAlgorithm("SHA256");
        //        bool rspRsa = rsaDeformatter.VerifySignature(hash, crypto);
        //        if (rspRsa)
        //        {
        //            logger.Debug("Signature validation successful");
        //        }
        //        else
        //        {
        //            logger.Error("Signature validation failed");
        //            return "Failure; Signature validation";
        //        }
        //    }
        //    catch (Exception)
        //    {
        //        logger.Error("Signature validation failed");
        //        return "Failure; Signature validation";
        //    }


        //    //verify remainder of JWT token
        //    var tokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters()
        //    {
        //        //ValidAudiences = new string[]
        //        //{
        //        //    clientId
        //        //},
        //        //ValidIssuers = new string[]
        //        //{
        //        //    issuer
        //        //},
        //        ValidAudience = audience,
        //        ValidIssuer = issuer,
        //        //IssuerSigningToken = new System.ServiceModel.Security.Tokens.BinarySecretSecurityToken(Convert.FromBase64String(secret)),
        //        //IssuerSigningKey = new X509SecurityKey(cert),
        //        RequireExpirationTime = true,
        //        ValidateLifetime = true,
        //        ValidateAudience = false,
        //        ValidateIssuer = true,
        //        ValidateIssuerSigningKey = false,
        //        RequireSignedTokens = false,
        //        CertificateValidator = System.IdentityModel.Selectors.X509CertificateValidator.None
        //    };



        //    try
        //    {
        //        // if token is valid, it will output the validated token that contains the JWT information
        //        // strip off signature from token
        //        string token1 = idToken.Substring(0, idToken.LastIndexOf('.') + 1);
        //        // Convert Base64 encoded token to Base64Url encoding
        //        string token2 = token1.Replace('+', '-').Replace('/', '_').Replace("=", "");
        //        System.Security.Claims.ClaimsPrincipal principal = tokenHandler.ValidateToken(token2, tokenValidationParameters, out validatedToken);
        //    }
        //    catch (Exception ex)
        //    {
        //        logger.Error("Failed to validate token");
        //        return "Failure; Validating token";
        //    }
        //    return payloadData.ToString();
        //}


        //private byte[] FromBase64Url(string base64Url)
        //{
        //    string padded = base64Url.Length % 4 == 0
        //        ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
        //    string base64 = padded.Replace("_", "/")
        //                            .Replace("-", "+");
        //    return Convert.FromBase64String(base64);
        //}

        //// from JWT spec
        //private byte[] Base64UrlDecode(string input)
        //{
        //    var output = input;
        //    output = output.Replace('-', '+'); // 62nd char of encoding
        //    output = output.Replace('_', '/'); // 63rd char of encoding
        //    switch (output.Length % 4) // Pad with trailing '='s
        //    {
        //        case 0: break; // No pad chars in this case
        //        case 1: output += "==="; break; // Three pad chars
        //        case 2: output += "=="; break; // Two pad chars
        //        case 3: output += "="; break; // One pad char
        //        default: throw new System.Exception("Illegal base64url string!");
        //    }
        //    var converted = Convert.FromBase64String(output); // Standard base64 decoder
        //    return converted;
        //}


        public bool SendTokenToWebApi(string access_token,  string destPage)
        {
            _logger.Debug("SendTokenToWebApiA");
            IRestResponse response = null;

            var client = new RestClient(destPage);
            var request = new RestRequest(Method.GET);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("Authorization", "Bearer " + access_token);
            response = client.Execute(request);

            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {
                return false;
            }


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