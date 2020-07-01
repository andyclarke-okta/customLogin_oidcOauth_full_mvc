using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace OIDC_CustomLogin.Controllers
{
    public class ConsentController : Controller
    {
        [HttpGet]
        public ActionResult tos()
        {
            return View();
        }


        [HttpGet]
        public ActionResult privacy()
        {
            return View();
        }
    }
}