using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OIDC_CustomLogin.Models
{


    public class TokenCallbackResponse
    {
        public List<Command> commands { get; set; }
        public Debugcontext debugContext { get; set; }
    }

    public class Debugcontext
    {
        public string extraParams { get; set; }
    }

    public class Command
    {
        public string type { get; set; }
        public List<Value> value { get; set; }
    }

    public class Value
    {
        public string op { get; set; }
        public string path { get; set; }
        public string value { get; set; }
    }



}