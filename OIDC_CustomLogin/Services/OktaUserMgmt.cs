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
using OIDC_CustomLogin.Models;
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
using RestSharp;

namespace OIDC_CustomLogin.Services
{
    public class OktaUserMgmt
    {

        private OktaSettings _orgSettings;
        private string _apiToken;
        private string _apiUrl;
        //private AuthClient _authclient;
        private UsersClient _usersClient;
        private OktaClient _oktaClient;
        //private SessionsClient _sessionsClient;
        //private UserFactorsClient _userFactorClient;

        //private static string _securityQuestion = "favorite_art_piece";
        //public static string _ppaPasswordResetAttrbiuteName;
        //public static int _passwordResetTokenExpiryDays;
        private static ILog _logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        public OktaUserMgmt(string apiUrl, string apiToken)
        {
            _apiUrl = apiUrl;
            Uri orgUri = new Uri(apiUrl);
            _orgSettings = new OktaSettings();
            _orgSettings.ApiToken = apiToken;
            _orgSettings.BaseUri = orgUri;
  
            _oktaClient = new OktaClient(_orgSettings);
            _usersClient = new UsersClient(_orgSettings);

        }

       // public string OrgUrl { get { return _apiUrl; } }

        //public User GetOktaUserById(string oktaId)
        //{
        //    User oktaUser = null;
        //    try
        //    {
        //        oktaUser = _usersClient.Get(oktaId);
        //    }
        //    catch (Exception ex)
        //    {
        //        _logger.Error(string.Format("Error searching for Okta user in Okta. Okta Id: {0}.", oktaId), ex);
        //    }

        //    return oktaUser;
        //}
        //public CustomUser GetCustomUser(string oktaId)
        //{
        //    User oktaUser = null;
        //    CustomUser customUser = null;

        //    try
        //    {

        //        oktaUser = _usersClient.Get(oktaId);
        //        customUser = new CustomUser(oktaUser);
        //        customUser.extProfile = new CustomUserProfile();

        //        List<string> customAttributes = oktaUser.Profile.GetUnmappedPropertyNames();
        //        foreach (var item in customAttributes)
        //        {

        //            PropertyInfo tempProp = customUser.extProfile.GetType().GetProperty(item);
        //            if (tempProp != null)
        //            {
        //                object myValue = oktaUser.Profile.GetProperty(item);
        //                if (tempProp.CanWrite)
        //                {
        //                    tempProp.SetValue(customUser.extProfile, myValue, null);
        //                }
        //            }
        //            else
        //            {
        //                _logger.Debug("unmapped okta attribute " + item + " is not defined as an extention");
        //            }

        //        }


        //    }
        //    catch (Exception ex)
        //    {
        //        _logger.Error(string.Format("Error searching for Okta user in Okta. Okta Id: {0}.", oktaId), ex);
        //    }

        //    return customUser;
        //}

        public PagedResults<User> ListBasicUsers(Uri nextPage = null)
        {
            PagedResults<User> oktaUserList = null;

            try
            {
                oktaUserList = _usersClient.GetList(nextPage, pageSize: 200);

            }
            catch (Exception ex)
            {
                _logger.Error("Error searching for Okta user in Okta. ");
            }

            return oktaUserList;
        }




        //public PagedResults<CustomUser> ListCustomUsersWithQuery(string query, Uri nextPage = null)
        //{
        //    PagedResults<User> oktaUserList = null;

        //    List<CustomUser> customUserList = new List<CustomUser>();
        //    CustomUser customUser = null;
        //    try
        //    {
        //        oktaUserList = _usersClient.GetList(nextPage, query: query, pageSize: 200);

        //        foreach (var user in oktaUserList.Results)
        //        {
        //            customUser = new CustomUser(user);
        //            customUser.extProfile = new CustomUserProfile();

        //            List<string> customAttributes = user.Profile.GetUnmappedPropertyNames();
        //            foreach (var item in customAttributes)
        //            {

        //                PropertyInfo tempProp = customUser.extProfile.GetType().GetProperty(item);
        //                if (tempProp != null)
        //                {
        //                    object myValue = user.Profile.GetProperty(item);
        //                    if (tempProp.CanWrite)
        //                    {
        //                        tempProp.SetValue(customUser.extProfile, myValue, null);
        //                    }
        //                }
        //                else
        //                {
        //                    _logger.Debug("unmapped okta attribute " + item + " is not defined as an extention");
        //                }

        //            }
        //        }


        //    }
        //    catch (Exception ex)
        //    {
        //        _logger.Error(string.Format("Error searching for Okta user in Okta. Okta username: {0}.", query), ex);
        //    }
        //    PagedResults<CustomUser> pagedCustomUserList = new PagedResults<CustomUser>(customUserList);
        //    return pagedCustomUserList;
        //}


        //public PagedResults<CustomUser> ListCustomUsersWithFilter(string filter, Uri nextPage = null)
        //{
        //    FilterBuilder filterBuilder = new FilterBuilder(filter);

        //    PagedResults<User> oktaUserList = null;

        //    List<CustomUser> customUserList = new List<CustomUser>();
        //    CustomUser customUser = null;
        //    try
        //    {
        //        oktaUserList = _usersClient.GetList(nextPage: nextPage, filter: filterBuilder, searchType: SearchType.Filter, pageSize: 200);

        //        foreach (var user in oktaUserList.Results)
        //        {
        //            customUser = new CustomUser(user);
        //            customUser.extProfile = new CustomUserProfile();

        //            List<string> customAttributes = user.Profile.GetUnmappedPropertyNames();
        //            foreach (var item in customAttributes)
        //            {

        //                PropertyInfo tempProp = customUser.extProfile.GetType().GetProperty(item);
        //                if (tempProp != null)
        //                {
        //                    object myValue = user.Profile.GetProperty(item);
        //                    if (tempProp.CanWrite)
        //                    {
        //                        tempProp.SetValue(customUser.extProfile, myValue, null);
        //                    }
        //                }
        //                else
        //                {
        //                    _logger.Debug("unmapped okta attribute " + item + " is not defined as an extention");
        //                }

        //            }
        //        }

        //    }
        //    catch (Exception ex)
        //    {
        //        _logger.Error(string.Format("Error searching for Okta user in Okta. Okta username: {0}.", filter), ex);
        //    }
        //    PagedResults<CustomUser> pagedCustomUserList = new PagedResults<CustomUser>(customUserList);
        //    return pagedCustomUserList;
        //}

        //public PagedResults<CustomUser> ListCustomUsersWithSearch(string searchType, string criteria, Uri nextPage = null)
        //{

        //    string encodedfilter = null;
        //    string stringFilter = criteria.ToString();
        //    encodedfilter = HttpUtility.UrlPathEncode(stringFilter);
        //    FilterBuilder filterBuilder = new FilterBuilder(encodedfilter);
        //    PagedResults<User> oktaUserList = null;
        //    List<CustomUser> customUserList = new List<CustomUser>();
        //    CustomUser customUser = null;
        //    try
        //    {
        //        if (searchType == "query")
        //        {
        //            oktaUserList = _usersClient.GetList(nextPage, query: criteria, pageSize: 200);
        //        }
        //        else if (searchType == "search")
        //        {
        //            oktaUserList = _usersClient.GetList(nextPage: nextPage, filter: filterBuilder, searchType: SearchType.ElasticSearch, pageSize: 200);
        //        }
        //        else if (searchType == "filter")
        //        {
        //            oktaUserList = _usersClient.GetList(nextPage: nextPage, filter: filterBuilder, searchType: SearchType.Filter, pageSize: 200);
        //        }



        //        foreach (var user in oktaUserList.Results)
        //        {
        //            customUser = new CustomUser(user);
        //            customUser.extProfile = new CustomUserProfile();

        //            List<string> customAttributes = user.Profile.GetUnmappedPropertyNames();
        //            foreach (var item in customAttributes)
        //            {

        //                PropertyInfo tempProp = customUser.extProfile.GetType().GetProperty(item);
        //                if (tempProp != null)
        //                {
        //                    object myValue = user.Profile.GetProperty(item);
        //                    if (tempProp.CanWrite)
        //                    {
        //                        tempProp.SetValue(customUser.extProfile, myValue, null);
        //                    }
        //                }
        //                else
        //                {
        //                    _logger.Debug("unmapped okta attribute " + item + " is not defined as an extention");
        //                }
        //                customUserList.Add(customUser);
        //            }
        //        }

        //    }
        //    catch (Exception ex)
        //    {
        //        _logger.Error(string.Format("Error searching for Okta user in Okta. Okta username: {0}.", criteria), ex);
        //    }
        //    PagedResults<CustomUser> pagedCustomUserList = new PagedResults<CustomUser>(customUserList);
        //    pagedCustomUserList.NextPage = oktaUserList.NextPage;
        //    pagedCustomUserList.PrevPage = oktaUserList.PrevPage;
        //    //pagedCustomUserList.RequestUri = oktaUserList.RequestUri;
        //    return pagedCustomUserList;


        //}

        //public CustomPagedResults<User> SearchCustomUsers(StringBuilder searchCriteria, Uri myUri = null)
        //{
        //    _logger.Debug("Search User criteria " + searchCriteria.ToString());
        //    //search user
        //    //users?search=
        //    //full profile including custom
        //    //id,status,created,activated,statusChanged,lastUpdated


        //    string encodedUrl = null;

        //    string stringFilter = searchCriteria.ToString();

        //    encodedUrl = HttpUtility.UrlPathEncode(stringFilter);

        //    string apiEndPoint = _orgUrl + Constants.EndpointV1 + Constants.UsersEndpoint + "?search=" + encodedUrl;
        //    Uri apiEndPointUri = new Uri(apiEndPoint);

        //    string httpStatus = null;
        //    //// CustomUser customUser = new CustomUser();
        //    ////customUser.profile = new Profile();
        //    //List<CustomUser> listCustomUser = new List<CustomUser>();
        //    List<User> listCustomUser = new List<User>();
        //    //RestClient client;
        //    //IRestResponse<List<CustomUser>> response;

        //    try
        //    {
        //        //if (myUri == null)
        //        //{
        //        //    //no Uri provided build it
        //        //    client = new RestClient(MvcApplication.apiUrl + "/api/v1/users?search=" + encodedUrl);
        //        //}
        //        //else
        //        //{
        //        //    //usr uri parameter
        //        //    client = new RestClient(myUri);
        //        //}

        //        //var request = new RestRequest(Method.GET);
        //        //request.AddHeader("Accept", "application/json");
        //        //request.AddHeader("Content-Type", "application/json");
        //        //request.AddHeader("Authorization", "SSWS " + MvcApplication.apiToken);
        //        //response = client.Execute<List<CustomUser>>(request);
        //        //httpStatus = response.StatusDescription;

        //        HttpResponseMessage response = _oktaClient.BaseClient.Get(apiEndPointUri);
        //        string responseTopContent = response.ToString();
        //        var index = responseTopContent.IndexOf(",", 20);
        //        var rspStatus = responseTopContent.Substring(0, index);
        //        string content = response.Content.ReadAsStringAsync().Result;
        //        _logger.Debug("response " + rspStatus + " content " + content);
        //        //listCustomUser = Utils.Deserialize<List<CustomUser>>(response);
        //        listCustomUser = Utils.Deserialize<List<User>>(response);


        //    }
        //    catch (Exception ex)
        //    {
        //        _logger.Error(ex.ToString());
        //        return null;
        //    }//end catch
             //if (httpStatus == "OK")
             //{
             //    //customUser = response.Data[0];
             //    listCustomUser = response.Data;
             // CustomPagedResults<CustomUser> customPagedResults = new CustomPagedResults<CustomUser>(listCustomUser);
           // CustomPagedResults<User> customPagedResults = new CustomPagedResults<User>(listCustomUser);
            //    //customPagedResults.Results = response.Data;
            //    customPagedResults.count = listCustomUser.Count;
            //    string self = null;
            //    string next = null;
            //    var headerList = response.Headers.ToList();
            //    string link = headerList.Find(x => x.Name == "Link").Value.ToString();


            //    int linkIndex = link.IndexOf(",");
            //    if (linkIndex > 0)
            //    {
            //        self = link.Substring(0, linkIndex);
            //    }
            //    else
            //    {
            //        self = link;
            //    }
            //    if (self.Contains("self"))
            //    {
            //        _logger.Debug("received selfLink: " + self);
            //        int selfIndex = self.IndexOf(">");
            //        string selfMod = self.Substring(1, selfIndex - 1);
            //        customPagedResults.RequestUri = new Uri(selfMod);
            //    }
            //    else
            //    {
            //        _logger.Error("Self link not found");
            //    }

            //    if (linkIndex > 0)
            //    {
            //        next = link.Substring(linkIndex + 1);
            //        if (next.Contains("next"))
            //        {
            //            _logger.Debug("received nextLink: " + next);
            //            int nextIndex = next.IndexOf(">");
            //            string nextMod = next.Substring(1, nextIndex - 1);
            //            customPagedResults.NextPage = new Uri(nextMod);
            //        }
            //        else
            //        {
            //            _logger.Debug("Next link not present");
            //        }
            //    }
            //    else
            //    {
            //        _logger.Debug("Next link not present");
            //    }

           // return customPagedResults;

            //}
            //else
            //{
            //    _logger.Error("Error in http call status:" + httpStatus);
            //    return null;
            //}
       // }



        //public bool SetupUserInOkta(string username, string password)
        //{
        //    bool success = false;
        //    CustomUser myUser = GetCustomUser(username);
        //    if (myUser != null)
        //    {
        //        // activate the user if not already activated - don't send activation email
        //        if (string.Equals(myUser.Status, "STAGED", StringComparison.InvariantCultureIgnoreCase))
        //        {
        //            _usersClient.Activate(myUser.Id, false);
        //        }

        //        // Update user's password
        //        _usersClient.SetPassword(myUser, password);
        //        success = true;
        //    }

        //    return success;
        //}

        public bool ActivateUser(string oktaId)
        {
            bool success = false;
            try
            {
                _usersClient.Activate(oktaId, false);
                success = true;
            }
            catch (Exception ex)
            {
                _logger.Error("Error activating user. {0}", ex);
            }

            return success;
        }


        //public bool ResetUserPassword(string oktaId, string password)
        //{
        //    bool success = false;

        //    try
        //    {
        //        User user = GetCustomUser(oktaId);
        //        _usersClient.SetPassword(user, password);
        //        success = true;
        //    }
        //    catch (OktaException ex)
        //    {
        //        _logger.Error("Error resetting user's password. {0}", ex);
        //    }

        //    return success;
        //}


        public bool UpdateOktaBaseUser(User oktaUser)
        {
            bool result = false;
            User oktaUserRsp = null;
            try
            {
                oktaUserRsp = _usersClient.Update(oktaUser);
                result = true;
            }
            catch (Exception ex)
            {
                _logger.Error(string.Format("Error updating Okta user. Okta username: {0}.", oktaUser.Profile.Login), ex);
            }

            return result;
        }

        /// <summary>
        /// SetCustomUserAttributes
        /// </summary>
        /// <param name="customUser"></param>
        /// <returns>bool</returns>

        //public bool SetCustomUserAttributes(CustomUser customUser)
        //{
        //    bool result = false;

        //    //User oktaUser = GetOktaUserById(oktaId);
        //    string oktaId = customUser.Id;
        //    string apiEndPoint = _orgUrl + Constants.EndpointV1 + Constants.UsersEndpoint + "/" + oktaId;

        //    CustomAttributes customAttributes = new CustomAttributes();
        //    customAttributes.Profile = customUser.extProfile;

        //    string serializedbody = JsonConvert.SerializeObject(customAttributes);

        //    try
        //    {

        //        // OktaHttpClient baseClient = new OktaHttpClient(_orgSettings);

        //        HttpResponseMessage response = _oktaClient.BaseClient.Post(apiEndPoint, serializedbody);
        //        string responseTopContent = response.ToString();
        //        var index = responseTopContent.IndexOf(",", 20);
        //        var rspStatus = responseTopContent.Substring(0, index);
        //        string content = response.Content.ReadAsStringAsync().Result;
        //        _logger.Debug("response " + rspStatus + " content " + content);
        //        result = true;
        //    }
        //    catch (Exception ex)
        //    {
        //        //_logger.Error(string.Format("Error updating Okta user. Okta username: {0}.", oktaUser.Profile.Login), ex);
        //    }

        //    return result;
        //}

        //public SecQuestionList GetSecurityQuestionList(string oktaId)
        //{
        //    ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        //    logger.Debug("query for security question ");
        //    User oktaUser = null;
        //    SecQuestionList mySecQuestionList = null;
        //    try
        //    {
        //        oktaUser = new User();
        //        // query okta for user record    
        //        OktaClient oktaClient = new OktaClient(MvcApplication.apiToken, MvcApplication.apiUrl);
        //        UsersClient usersClient = oktaClient.GetUsersClient();
        //        oktaUser = usersClient.Get(oktaId);
        //        UserFactorsClient userFactorClient = oktaClient.GetUserFactorsClient(oktaUser);
        //        List<Question> listQuestionRsp = userFactorClient.GetQuestions();
        //        mySecQuestionList = new SecQuestionList() { listSecQuestion = listQuestionRsp };
        //    }
        //    catch (OktaException ex)
        //    {
        //        logger.Error(" ErrorCode: " + ex.ErrorCode + " " + ex.ErrorSummary);

        //    }//end catch
        //    return mySecQuestionList;
        //}


        //public CustomUserProfileExt CreateNewUser(RegistrationViewModel registrationViewModel, string activation_passCode, string activation_setDate)
        //{

        //    logger.Debug("CreateNewUser email " + registrationViewModel.Email);

        //    CustomUserProfileExt customUserProfileExt = new CustomUserProfileExt();
        //    SetCustomUser setCustomUser = new SetCustomUser();
        //    setCustomUser.profile = new CustomUserProfile();
        //    IRestResponse<CustomUser> response = null;
        //    bool rspRateLimitCheck = false;


        //    //populate custom profile to create user
        //    setCustomUser.profile.login = registrationViewModel.Email;
        //    setCustomUser.profile.email = registrationViewModel.Email;
        //    setCustomUser.profile.firstName = registrationViewModel.FirstName;
        //    setCustomUser.profile.lastName = registrationViewModel.LastName;
        //    setCustomUser.profile.middleName = registrationViewModel.MiddleName;
        //    setCustomUser.profile.addressType = registrationViewModel.MailingAddress.Type;
        //    setCustomUser.profile.streetAddress = registrationViewModel.MailingAddress.Street1;
        //    setCustomUser.profile.streetAddress2 = registrationViewModel.MailingAddress.Street2;
        //    setCustomUser.profile.streetAddress3 = registrationViewModel.MailingAddress.Street3;
        //    setCustomUser.profile.city = registrationViewModel.MailingAddress.City;
        //    setCustomUser.profile.state = registrationViewModel.MailingAddress.State;
        //    setCustomUser.profile.zipCode = registrationViewModel.MailingAddress.ZIP;
        //    setCustomUser.profile.countryCode = registrationViewModel.MailingAddress.Country;
        //    setCustomUser.profile.province = registrationViewModel.MailingAddress.Province;
        //    setCustomUser.profile.primaryPhone = registrationViewModel.Phone.Phone;
        //    setCustomUser.profile.primaryExt = registrationViewModel.Phone.Extension;
        //    setCustomUser.profile.preferredContact = registrationViewModel.PreferredContact;
        //    setCustomUser.profile.isCIMAMember = registrationViewModel.IsCIMAMember.ToString();
        //    setCustomUser.profile.CIMANumber = registrationViewModel.CIMANumber;
        //    setCustomUser.profile.activation_passCode = activation_passCode;
        //    setCustomUser.profile.activation_setDate = activation_setDate;


        //    try
        //    {
        //        do
        //        {
        //            var client = new RestClient(MvcApplication.apiUrl + "api/v1/users/?activate=false");
        //            var request = new RestRequest(Method.POST);
        //            request.AddHeader("Accept", "application/json");
        //            request.AddHeader("Content-Type", "application/json");
        //            request.AddHeader("Authorization", " SSWS " + MvcApplication.apiToken);
        //            //create json body to add profile to creation api
        //            request.AddJsonBody(setCustomUser);

        //            response = client.Execute<CustomUser>(request);
        //            if (response.StatusCode.ToString() == "429")
        //            {
        //                rspRateLimitCheck = Toolbox.RateLimitCheck(response);
        //            }
        //            else
        //            {
        //                rspRateLimitCheck = false;
        //            }
        //        } while (rspRateLimitCheck);


        //        if (!string.IsNullOrEmpty(response.Data.status))
        //        {
        //            customUserProfileExt.id = response.Data.id;
        //            customUserProfileExt.email = response.Data.profile.email;
        //            customUserProfileExt.login = response.Data.profile.login;
        //            customUserProfileExt.lastName = response.Data.profile.lastName;
        //            customUserProfileExt.firstName = response.Data.profile.firstName;
        //            customUserProfileExt.activation_status = response.Data.status;
        //            customUserProfileExt.activation_passCode = response.Data.profile.activation_passCode;

        //            logger.Debug("oktaUser.Status: " + response.Data.status);
        //            return customUserProfileExt;
        //        }
        //        else
        //        {
        //            logger.Error("Did not receive status from api for create user " + registrationViewModel.Email);
        //            return null;
        //        }
        //    }
        //    catch (OktaException ex)
        //    {
        //        logger.Error("Error Creating User " + registrationViewModel.Email + " Code: " + ex.ErrorCode + " " + ex.ErrorSummary);
        //        return null;
        //    }//end catch
        //}


        //internal static CustomUserProfileExt CheckCustomUserProfile(string oktaId)
        //{
        //    ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        //    NameValueCollection appSettings = ConfigurationManager.AppSettings;
        //    logger.Debug("CheckCustomUserProfile oktaId " + oktaId);

        //    CustomUserProfileExt customUserProfileExt = new CustomUserProfileExt();
        //CustomUser customUser = new CustomUser();
        //customUser.extProfile = new CustomUserProfile();
        //IRestResponse<CustomUser> response = null;

        //try
        //{


        //var client = new RestClient(MvcApplication.apiUrl + Constants.EndpointV1 + Constants.UsersEndpoint + "/" + oktaId);
        //var request = new RestRequest(Method.GET);
        //request.AddHeader("Accept", "application/json");
        //request.AddHeader("Content-Type", "application/json");
        //request.AddHeader("Authorization", " SSWS " + MvcApplication.apiToken);
        //response = client.Execute<CustomUser>(request);

        //if (!string.IsNullOrEmpty(response.Data.Profile.hd_verification_question) || !string.IsNullOrEmpty(response.Data.Profile.hd_verification_answer))
        //{
        //    customUserProfileExt.hd_verification_question = response.Data.Profile.hd_verification_question;
        //    customUserProfileExt.hd_verification_answer = response.Data.Profile.hd_verification_answer;
        //    customUserProfileExt.hd_status = "HelpDeskQuestionSet";
        //}
        //else
        //{
        //    customUserProfileExt.hd_status = "HelpDeskQuestionNotSet";
        //}
        //if (!string.IsNullOrEmpty(response.Data.Profile.emailAuth_passCode) || !string.IsNullOrEmpty(response.Data.Profile.emailAuth_setDate))
        //{
        //    customUserProfileExt.emailAuth_passCode = response.Data.Profile.emailAuth_passCode;
        //    customUserProfileExt.emailAuth_setDate = response.Data.Profile.emailAuth_setDate;
        //    customUserProfileExt.emailAuth_status = "EmailAuthSet";
        //}
        //else
        //{
        //    customUserProfileExt.emailAuth_status = "EmailAuthNotSet";
        //}

        //return customUserProfileExt;

        //    }
        //    catch (OktaException ex)
        //    {
        //        logger.Error(" ErrorCode: " + ex.ErrorCode + " " + ex.ErrorSummary);
        //        return null;
        //    }//end catch


        //}

        //internal static bool SetCustomUserProfile(string oktaId, CustomUserProfile customUserProfile)
        //{
        //    ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        //    NameValueCollection appSettings = ConfigurationManager.AppSettings;
        //    logger.Debug("SetCustomUserProfile oktaId " + oktaId);

        //CustomUserProfileExt customUserProfileExt = new CustomUserProfileExt();
        //CustomUser customUser = new CustomUser();
        //customUser.extProfile = customUserProfile;
        //IRestResponse<CustomUser> response = null;

        //try
        //{
        //    var client = new RestClient(MvcApplication.apiUrl + Constants.EndpointV1 + Constants.UsersEndpoint + "/" + oktaId);
        //    var request = new RestRequest(Method.POST);
        //    request.AddHeader("Accept", "application/json");
        //    request.AddHeader("Content-Type", "application/json");
        //    request.AddHeader("Authorization", " SSWS " + MvcApplication.apiToken);
        //    request.AddJsonBody(customUser);
        //    response = client.Execute<CustomUser>(request);

        //}
        //catch (OktaException ex)
        //{
        //    logger.Error(" ErrorCode: " + ex.ErrorCode + " " + ex.ErrorSummary);
        //    return false;
        //}//end catch
        //        return true;
        //    }


        //internal static MinUserProfile CheckUserProfile(string oktaUserName)
        //{
        //    ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        //    logger.Debug("CheckUserProfile oktaUserName " + oktaUserName);

        //    User oktaUser = null;
        //    MinUserProfile response = new MinUserProfile();
        //    //check user profile

        //    try
        //    {
        //        oktaUser = new User();
        //        // query okta for user record    
        //        OktaClient oktaClient = new OktaClient(MvcApplication.apiToken, MvcApplication.apiUrl);
        //        UsersClient usersClient = oktaClient.GetUsersClient();

        //        oktaUser = usersClient.Get(oktaUserName);
        //    }
        //    catch (OktaException ex)
        //    {
        //        logger.Error(" ErrorCode: " + ex.ErrorCode + " " + ex.ErrorSummary);
        //        response.status = "ERROR";
        //        return response;
        //    }//end catch

        //    response.id = oktaUser.Id;

        //    logger.Debug("oktaUser.Status: " + oktaUser.Status);
        //    switch (oktaUser.Status)
        //    {
        //        case "DEPROVISIONED":
        //            response.status = "DEPROVISIONED";
        //            break;
        //        case "ACTIVE":
        //            logger.Debug("check for Sec Question");
        //            if (string.IsNullOrEmpty(oktaUser.Credentials.RecoveryQuestion.Question))
        //            {
        //                response.status = "ACTIVE_SecQuestionNotSet";
        //            }
        //            else
        //            {
        //                response.status = "ACTIVE_SecQuestionSet";
        //            }
        //            break;
        //        default:
        //            response.status = oktaUser.Status;
        //            break;
        //    }
        //    return response;
        //}

    }
}