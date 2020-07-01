using Okta.Core.Clients;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace OIDC_CustomLogin
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            GlobalConfiguration.Configure(WebApiConfig.Register);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            log4net.Config.XmlConfigurator.Configure(new FileInfo(Server.MapPath("~/Web.config")));

            System.Net.ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;


        }


      //  public static string apiToken = ConfigurationManager.AppSettings["okta.apiToken"];
      //  public static Uri apiUrl = new System.Uri(ConfigurationManager.AppSettings["okta.apiUrl"]);


    }
}
