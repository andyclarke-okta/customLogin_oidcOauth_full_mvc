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

namespace OIDC_CustomLogin.Services
{
    public class OktaAuthMgmt
    {

        private OktaSettings _orgSettings;
        private string _apiToken;
        private string _orgUrl;
        private AuthClient _authclient;
        private UsersClient _usersClient;
        private OktaClient _oktaClient;
        private SessionsClient _sessionsClient;
        private UserFactorsClient _userFactorClient;

        //private static string _securityQuestion = "favorite_art_piece";
        //public static string _ppaPasswordResetAttrbiuteName;
        //public static int _passwordResetTokenExpiryDays;
        private static ILog _logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        public OktaAuthMgmt(string orgUrlParam, string apiToken)
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
            // _passwordResetTokenExpiryDays = int.Parse(ConfigurationManager.AppSettings["okta.passwordresettokenlifetime"]);
            //_ppaPasswordResetAttrbiuteName = ConfigurationManager.AppSettings["ppa.passwordresetoktaattribute"];
        }

        //public static int PasswordResetTokenExpiryDays { get { return _passwordResetTokenExpiryDays; } }

        //public static string PpaPasswordResetAttrbiuteName { get { return _ppaPasswordResetAttrbiuteName; } }
        public string OrgUrl { get { return _orgUrl; } }


        public AuthResponse Enroll(string stateToken, Factor factor)
        {
            return _authclient.Enroll(stateToken, factor);
        }
        public AuthResponse GetStatus(string stateToken)
        {
            return _authclient.GetStatus(stateToken);
        }
        public AuthResponse AuthenticateUser(string username, string password, string relayState = null, bool bWarnPasswordExpired = false, bool bMultiOptionalFactorEnroll = false)
        {
            AuthResponse userAuthClientRsp = null;
            userAuthClientRsp = _authclient.Authenticate(username, password, relayState, bWarnPasswordExpired, bMultiOptionalFactorEnroll);
            _logger.Debug("thisAuth status " + userAuthClientRsp.Status);
            return userAuthClientRsp;
        }

        public AuthResponse Execute(string stateToken, string link, ApiObject apiObject = null)
        {
            Link href = new Link();
            href.Href = new Uri(link);
            return _authclient.Execute(stateToken, href, apiObject);
        }

        public AuthResponse Execute(string stateToken, Link link, ApiObject apiObject = null)
        {
            return _authclient.Execute(stateToken, link, apiObject);
        }

        public AuthResponse VerifyEmailMFA(string verificationCode, string verifyLink)
        {
            AuthResponse tempRsp = new AuthResponse();
            return tempRsp;

            //Uri veriyUri = new Uri(verifyLink);
            //return authclient.VerifyQuestionFactor(verificationCode, veriyUri);
        }

        public AuthResponse ChangePasswordAuth(string oldPassword, string newPassword, string stateToken)
        {
            AuthResponse tempRsp = new AuthResponse();
            return tempRsp;

            //string resourcePath = OrgUrl + Constants.EndpointV1 + Constants.AuthnEndpoint + Constants.CredentialsChangePasswordEndpoint;
            //return authclient.ChangePasswordAuth(oldPassword, newPassword, stateToken, resourcePath);
        }
        public AuthResponse UnlockAccountAuth(string username, string factorType, string relayState)
        {

            AuthResponse tempRsp = new AuthResponse();
            return tempRsp;

            //string resourcePath = OrgUrl + Constants.EndpointV1 + Constants.AuthnEndpoint + Constants.RecoveryEndpoint + Constants.UnlockEndpoint;
            //return authclient.UnlockAccountAuth(username, factorType, relayState, new Uri(resourcePath));
        }

        public AuthResponse ForgotPasswordAuth(string username, string factorType, string relayState)
        {
            AuthResponse tempRsp = new AuthResponse();
            return tempRsp;

            //string resourcePath = OrgUrl + Constants.EndpointV1 + Constants.AuthnEndpoint + Constants.RecoveryEndpoint + Constants.PasswordEndpoint;
            //return authclient.UnlockAccountAuth(username, factorType, relayState, new Uri(resourcePath));
        }


        public AuthResponse UnlockVerifyAuth(string username, string token)
        {
            AuthResponse tempRsp = new AuthResponse();
            return tempRsp;

            //string resourcePath = OrgUrl + Constants.EndpointV1 + Constants.AuthnEndpoint + Constants.RecoveryEndpoint + Constants.FactorsEndpoint + Constants.SmsEndpoint + Constants.VerifyEndpoint;
            //return authclient.UnlockVerifyAuth(username, token, new Uri(resourcePath));
        }

        public AuthResponse UnlockQuestionAuth(string verifyAnswer, string token)
        {
            AuthResponse tempRsp = new AuthResponse();
            return tempRsp;

            //string resourcePath = OrgUrl + Constants.EndpointV1 + Constants.AuthnEndpoint + Constants.RecoveryEndpoint + Constants.AnswerEndpoint;
            //return authclient.UnlockQuestionAuth(verifyAnswer, token, new Uri(resourcePath));
        }

        public AuthResponse ResetPasswordAuth(string newPassword, string stateToken)
        {
            AuthResponse tempRsp = new AuthResponse();
            return tempRsp;

            //string resourcePath = OrgUrl + Constants.EndpointV1 + Constants.AuthnEndpoint + Constants.CredentialsEndpoint + Constants.CredentialsResetPasswordEndpoint;
            //return authclient.ResetPasswordAuth(newPassword, stateToken, new Uri(resourcePath));
        }

        public AuthResponse ActivatePasscodeFactor(string stateToken, string passCode, string activateUri)
        {
            AuthResponse tempRsp = new AuthResponse();
            return tempRsp;

            //return authclient.ActivatePasscodeFactor(stateToken, passCode, new Uri(activateUri));
        }


    }
}