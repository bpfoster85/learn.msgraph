using Microsoft.AspNetCore.Authorization;
using System.Data;

namespace CallMSGraph
{
    public class MyAuthorizationAttribute : AuthorizeAttribute
    {
        private string _myKeys;
        public string MyKeys
        {
            get { return _myKeys; }
            set
            {
                Roles = value;
            }
        }
    }
}
