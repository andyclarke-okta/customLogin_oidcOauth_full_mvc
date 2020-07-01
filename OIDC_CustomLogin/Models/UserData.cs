using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OIDC_CustomLogin.Models
{
    public class MinUserProfile
    {
        public string status { get; set; }
        public string id { get; set; }
    }

    public class MinHelpDeskProfile
    {
        public string hd_verification_question { get; set; }
        public string hd_verification_answer { get; set; }
        public string status { get; set; }
    }



    public class CreateUserRequest
    {
        public string sessionToken { get; set; }
    }




    public class CreateUserResponse
    {
        public string id { get; set; }
        public string status { get; set; }
        public DateTime created { get; set; }
        public DateTime activated { get; set; }
        public DateTime statusChanged { get; set; }
        public DateTime lastLogin { get; set; }
        public DateTime lastUpdated { get; set; }
        public DateTime passwordChanged { get; set; }
        public Profile1 profile { get; set; }
        public Credentials1 credentials { get; set; }
        public _Links1 _links { get; set; }
    }

    public class Profile1
    {
        public string firstName { get; set; }
        public string lastName { get; set; }
        public object mobilePhone { get; set; }
        public string login { get; set; }
        public string email { get; set; }
        public object secondEmail { get; set; }
        public string middleName { get; set; }
        public string division { get; set; }
        public string[] RolesArray { get; set; }
        public string ascoid { get; set; }
        public string department { get; set; }
        public string employeeNumber { get; set; }
        public string primaryPhone { get; set; }
        public string streetAddress { get; set; }
        public string city { get; set; }
        public string state { get; set; }
        public string zipCode { get; set; }
        public string countryCode { get; set; }
    }

    public class Credentials1
    {
        public Password1 password { get; set; }
        public Recovery_Question1 recovery_question { get; set; }
        public Provider1 provider { get; set; }
    }

    public class Password1
    {
    }

    public class Recovery_Question1
    {
        public string question { get; set; }
    }

    public class Provider1
    {
        public string type { get; set; }
        public string name { get; set; }
    }

    public class _Links1
    {
        public Suspend1 suspend { get; set; }
        public Resetpassword1 resetPassword { get; set; }
        public Expirepassword1 expirePassword { get; set; }
        public Forgotpassword1 forgotPassword { get; set; }
        public Self1 self { get; set; }
        public Changerecoveryquestion1 changeRecoveryQuestion { get; set; }
        public Deactivate1 deactivate { get; set; }
        public Changepassword1 changePassword { get; set; }
    }

    public class Suspend1
    {
        public string href { get; set; }
        public string method { get; set; }
    }

    public class Resetpassword1
    {
        public string href { get; set; }
        public string method { get; set; }
    }

    public class Expirepassword1
    {
        public string href { get; set; }
        public string method { get; set; }
    }

    public class Forgotpassword1
    {
        public string href { get; set; }
        public string method { get; set; }
    }

    public class Self1
    {
        public string href { get; set; }
    }

    public class Changerecoveryquestion1
    {
        public string href { get; set; }
        public string method { get; set; }
    }

    public class Deactivate1
    {
        public string href { get; set; }
        public string method { get; set; }
    }

    public class Changepassword1
    {
        public string href { get; set; }
        public string method { get; set; }
    }


}