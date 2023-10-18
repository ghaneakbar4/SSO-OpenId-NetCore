using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ExampleOpenIDClient.Pages
{
    public class AboutModel : PageModel
    {
        private readonly IConfiguration _configuration;

        public string? MetadataUrl { get; set; }

        public AboutModel(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public void OnGet()
        {
            MetadataUrl = new Uri(new Uri(_configuration.GetValue<string>("OpenID:Authority")), ".well-known/openid-configuration").ToString();
        }
    }
}
