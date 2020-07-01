

using Newtonsoft.Json;
using System.Collections.Specialized;
using System.Configuration;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Web.Http.ExceptionHandling;

namespace OIDC_CustomLogin
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );


            // CORS
            // TODO: can get the trusted CORS origins from Okta Trusted Origins API
            var origins = ConfigurationManager.AppSettings["cors:origins"];
            var corsPolicy = new EnableCorsAttribute(origins, "*", "*") { SupportsCredentials = true };
            config.EnableCors(corsPolicy);

            // custom JSON settings
            //var serializerSettings = config.Formatters.JsonFormatter.SerializerSettings;
            //serializerSettings.NullValueHandling = NullValueHandling.Ignore;
            //serializerSettings.DefaultValueHandling = DefaultValueHandling.Ignore;
            //serializerSettings.DateTimeZoneHandling = DateTimeZoneHandling.Utc;
            //serializerSettings.DateFormatHandling = DateFormatHandling.IsoDateFormat;
            //serializerSettings.Converters.Add(new LinkListConverter());

            // custom exception handling
            //config.Services.Replace(typeof(IExceptionHandler), new OktaExceptionHandler());




        }
    }
}
