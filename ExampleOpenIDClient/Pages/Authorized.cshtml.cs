using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http.Headers;
using System.Text.Json;

namespace ExampleOpenIDClient.Pages
{
    [Authorize]
    public class AuthorizedModel : PageModel
    {
        public class ProductInformation
        {
            public string? Name { get; set; }
            public string? Version { get; set; }
            public bool IsLicensed { get; set; }
            public DateTime Expires { get; set; }
            public string? DisplayMessage { get; set; }
        }

        private readonly IConfiguration _configuration;

        private readonly IHttpClientFactory _httpClientFactory;

        public AuthorizedModel(IConfiguration configuration, IHttpClientFactory httpClientFactory)
        {
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
        }

        public string? ProductDisplayMessage { get; set; }

        public async Task OnGetAsync()
        {
            var url = _configuration["OpenID:Authority"];

            if (url is null)
            {
                throw new Exception("The OpenID authority is missing from the configuration.");
            }

            url = $"{url}/api/license";

            var accesstoken = await HttpContext.GetTokenAsync("access_token");

            if (accesstoken is null)
            {
                throw new Exception("There is no access token.");
            }

            var httpClient = _httpClientFactory.CreateClient();
            
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, url);

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accesstoken);

            var httpResponseMessage = await httpClient.SendAsync(httpRequestMessage);

            httpResponseMessage.EnsureSuccessStatusCode();

            var productInformation = await JsonSerializer.DeserializeAsync<ProductInformation>(
                await httpResponseMessage.Content.ReadAsStreamAsync(),
                new JsonSerializerOptions()
                {
                    PropertyNameCaseInsensitive = true
                });

            if (productInformation is null)
            {
                throw new Exception("No product information was returned by the OpenID Provider.");
            }

            ProductDisplayMessage = productInformation.DisplayMessage;
        }
    }
}
