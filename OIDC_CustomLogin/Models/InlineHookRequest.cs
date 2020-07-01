using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OIDC_CustomLogin.Models
{


    public class TokenCallbackRequest
    {
        public string eventTypeVersion { get; set; }
        public string cloudEventVersion { get; set; }
        public string eventType { get; set; }
        public string contentType { get; set; }
        public string source { get; set; }
        public string eventId { get; set; }
        public DateTime eventTime { get; set; }
        public Data data { get; set; }
    }

    public class Data
    {
        public Context context { get; set; }
        public Tokens tokens { get; set; }
    }

    public class Context
    {
        public Request request { get; set; }
        public Protocol protocol { get; set; }
        public Session1 session { get; set; }
        public User1 user { get; set; }
        public Policy policy { get; set; }
    }

    public class Request
    {
        public string id { get; set; }
        public string method { get; set; }
        public Url url { get; set; }
        public string ipAddress { get; set; }
    }

    public class Url
    {
        public string value { get; set; }
    }

    public class Protocol
    {
        public string type { get; set; }
        public Request1 request { get; set; }
        public Issuer issuer { get; set; }
        public Client client { get; set; }
    }

    public class Request1
    {
        public string scope { get; set; }
        public string state { get; set; }
        public string redirect_uri { get; set; }
        public string response_mode { get; set; }
        public string response_type { get; set; }
        public string client_id { get; set; }
    }

    public class Issuer
    {
        public string uri { get; set; }
    }

    public class Client
    {
        public string id { get; set; }
        public string name { get; set; }
        public string type { get; set; }
    }

    public class Session1
    {
        public string id { get; set; }
        public string userId { get; set; }
        public string login { get; set; }
        public DateTime createdAt { get; set; }
        public DateTime expiresAt { get; set; }
        public string status { get; set; }
        public DateTime lastPasswordVerification { get; set; }
        public DateTime lastFactorVerification { get; set; }
        public string[] amr { get; set; }
        public Idp1 idp { get; set; }
        public bool mfaActive { get; set; }
    }

    public class Idp1
    {
        public string id { get; set; }
        public string type { get; set; }
    }

    public class User1
    {
        public string id { get; set; }
        public DateTime passwordChanged { get; set; }
        public Profile2 profile { get; set; }
        public _Links2 _links { get; set; }
    }

    public class Profile2
    {
        public string login { get; set; }
        public string firstName { get; set; }
        public string lastName { get; set; }
        public string locale { get; set; }
        public string timeZone { get; set; }
    }

    public class _Links2
    {
        public Groups groups { get; set; }
        public Factors factors { get; set; }
    }

    public class Groups
    {
        public string href { get; set; }
    }

    public class Factors
    {
        public string href { get; set; }
    }

    public class Policy
    {
        public string id { get; set; }
        public Rule rule { get; set; }
    }

    public class Rule
    {
        public string id { get; set; }
    }

    public class Tokens
    {
        public Access_Token access_token { get; set; }
        public Id_Token id_token { get; set; }
    }

    public class Access_Token
    {
        public Claims claims { get; set; }
        public Lifetime lifetime { get; set; }
        public Scopes scopes { get; set; }
    }

    public class Claims
    {
        public int ver { get; set; }
        public string jti { get; set; }
        public string iss { get; set; }
        public string aud { get; set; }
        public string cid { get; set; }
        public string uid { get; set; }
        public string sub { get; set; }
        public string patientId { get; set; }
        public object[] appProfile { get; set; }
        public string claim1 { get; set; }
    }

    public class Lifetime
    {
        public int expiration { get; set; }
    }

    public class Scopes
    {
        public ProvidersRead providersread { get; set; }
        public Address2 address { get; set; }
        public Phone phone { get; set; }
        public Openid openid { get; set; }
        public Profile3 profile { get; set; }
        public Email email { get; set; }
    }

    public class ProvidersRead
    {
        public string id { get; set; }
        public string action { get; set; }
    }

    public class Address2
    {
        public string id { get; set; }
        public string action { get; set; }
    }

    public class Phone
    {
        public string id { get; set; }
        public string action { get; set; }
    }

    public class Openid
    {
        public string id { get; set; }
        public string action { get; set; }
    }

    public class Profile3
    {
        public string id { get; set; }
        public string action { get; set; }
    }

    public class Email
    {
        public string id { get; set; }
        public string action { get; set; }
    }

    public class Id_Token
    {
        public Claims1 claims { get; set; }
        public Lifetime1 lifetime { get; set; }
    }

    public class Claims1
    {
        public string sub { get; set; }
        public string name { get; set; }
        public string email { get; set; }
        public int ver { get; set; }
        public string iss { get; set; }
        public string aud { get; set; }
        public string jti { get; set; }
        public string[] amr { get; set; }
        public string idp { get; set; }
        public string nonce { get; set; }
        public string preferred_username { get; set; }
        public int auth_time { get; set; }
    }

    public class Lifetime1
    {
        public int expiration { get; set; }
    }




}