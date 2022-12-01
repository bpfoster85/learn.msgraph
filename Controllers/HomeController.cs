using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using WebApp_OpenIDConnect_DotNet_graph.Models;

namespace WebApp_OpenIDConnect_DotNet_graph.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        private readonly GraphServiceClient _graphServiceClient;

        private readonly MicrosoftIdentityConsentAndConditionalAccessHandler _consentHandler;

        private string[] _graphScopes;

        public HomeController(ILogger<HomeController> logger,
                            IConfiguration configuration,
                            GraphServiceClient graphServiceClient,
                            MicrosoftIdentityConsentAndConditionalAccessHandler consentHandler)
        {
            _logger = logger;
            _graphServiceClient = graphServiceClient;
            this._consentHandler = consentHandler;

            // Capture the Scopes for Graph that were used in the original request for an Access token (AT) for MS Graph as
            // they'd be needed again when requesting a fresh AT for Graph during claims challenge processing
            _graphScopes = configuration.GetValue<string>("DownstreamApi:Scopes")?.Split(' ');
        }

        [AuthorizeForScopes(ScopeKeySection = "DownstreamApi:Scopes")]
        public IActionResult Index()
        {
            return View(User?.Claims);
        }

        [AuthorizeForScopes(ScopeKeySection = "DownstreamApi:Scopes")]
        public async Task<IActionResult> Profile()
        {
            User currentUser = null;

            try
            {
                currentUser = await _graphServiceClient.Me.Request().GetAsync();
            }
            // Catch CAE exception from Graph SDK
            catch (ServiceException svcex) when (svcex.Message.Contains("Continuous access evaluation resulted in claims challenge"))
            {
                try
                {
                    Console.WriteLine($"{svcex}");
                    string claimChallenge = WwwAuthenticateParameters.GetClaimChallengeFromResponseHeaders(svcex.ResponseHeaders);
                    _consentHandler.ChallengeUser(_graphScopes, claimChallenge);
                    return new EmptyResult();
                }
                catch (Exception ex2)
                {
                    _consentHandler.HandleException(ex2);
                }
            }

            try
            {
                // Get user photo
                using (var photoStream = await _graphServiceClient.Me.Photo.Content.Request().GetAsync())
                {
                    byte[] photoByte = ((MemoryStream)photoStream).ToArray();
                    ViewData["Photo"] = Convert.ToBase64String(photoByte);
                }
            }
            catch (Exception pex)
            {
                Console.WriteLine($"{pex.Message}");
                ViewData["Photo"] = null;
            }
            var groups = await _graphServiceClient.Groups
                .Request()
                .Filter("startswith(displayName, 'ams')")
                .Select(g => new { g.DisplayName, g.Id })
                .GetAsync();

            List<string> groupNames = groups.Select(g => g.DisplayName).ToList();
            ViewData["groups"] = groupNames;


            string[] groupIds = groups.Select(g => g.Id).ToArray();
            var queryOptions = new List<QueryOption>()
                {
                    new QueryOption("$count", "true")
                };
            var groupMembers = await _graphServiceClient.Groups[groupIds[1]].Members
                .Request(queryOptions)
                .Header("ConsistencyLevel", "eventual")
                .Select("displayName")
                .OrderBy("displayName")
                .GetAsync();

            List<Microsoft.Graph.DirectoryObject> members = (List<Microsoft.Graph.DirectoryObject>)groupMembers.ToList();
            List<Microsoft.Graph.User> users = new List<User>();
            foreach (Microsoft.Graph.DirectoryObject member in members)
            {
                Microsoft.Graph.User user = (Microsoft.Graph.User)member;
                users.Add(user);
            }
            ViewData["groupmembers"] = users;
            ViewData["Me"] = currentUser;
            return View();
        }
        [Authorize(Roles ="App.Role.2")]
        public IActionResult Privacy()
        {
            return View();
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private string GetSecretFromKeyVault()
        {
            string uri = Environment.GetEnvironmentVariable("KEY_VAULT_URI");
            SecretClient client = new SecretClient(new Uri(uri), new DefaultAzureCredential());

            Response<KeyVaultSecret> secret = client.GetSecretAsync("Graph-App-Secret").Result;

            return secret.Value.Value;
        }

    }
}