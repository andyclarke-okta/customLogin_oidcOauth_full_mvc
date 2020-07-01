using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using OIDC_CustomLogin.Models;

namespace OIDC_CustomLogin.Controllers
{
    [RoutePrefix("api/v1")]
    public class InlineHookController : ApiController
    {

        [HttpPost]
        [Route("tokenhook")]
        public TokenCallbackResponse TokenHook([FromBody]TokenCallbackRequest request)
        //public AuthResponse PasswordRecovery(ExtendedAuthRequest request, string appName = DefaultAppName)
        {
            TokenCallbackResponse callbackResponse = new TokenCallbackResponse();
            string myParams = null;

            //extract extraParams from request
            string myUrl = request.data.context.request.url.value;
            int index1 = myUrl.IndexOf("&extra_param=");
            string partial = myUrl.Substring(index1 + 13);
            int index2 = partial.IndexOf("&");
            if (index2 > 0)
            {
                myParams = partial.Substring(0, index2);
            }
            else
            {
                myParams = partial;
            }
            

            // use passed in myParams to add user info to token
            // put any additional processing here, keep latency to a minimum


            //mock up sample response json
            callbackResponse.commands = new List<Command>();

            Command command1 = new Command();
            command1.type = "com.okta.identity.patch";
            command1.value = new List<Value>();
            Value value1 = new Value();
            value1.op = "add";
            value1.path = "/claims/extUserId";
            value1.value = "1234_useridentifier_5678";
            command1.value.Add(value1);
           // callbackResponse.commands.Add(command1);

            Command command2 = new Command();
            command2.type = "com.okta.access.patch";
            command2.value = new List<Value>();
            Value value2 = new Value();
            value2.op = "add";
            value2.path = "/claims/extUserIdentifier";
            //value2.value = "myUserInfo_1234";
            value2.value = myParams;
            command2.value.Add(value2);

            callbackResponse.commands.Add(command2);
           

            callbackResponse.debugContext = new Debugcontext();
            callbackResponse.debugContext.extraParams = "myDebugInfo";

            return callbackResponse;
        }



        // GET: api/InlineHook
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET: api/InlineHook/5
        public string Get(int id)
        {
            return "value";
        }

        // POST: api/InlineHook
        public void Post([FromBody]string value)
        {
        }

        // PUT: api/InlineHook/5
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE: api/InlineHook/5
        public void Delete(int id)
        {
        }
    }
}
