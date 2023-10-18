using ComponentSpace.OpenID.Utility;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ExampleOpenIDProvider.Pages
{
    public class AboutModel : PageModel
    {
        public AboutModel(ILicense license)
        {
            string licenseType;

            if (license.IsLicensed)
            {
                licenseType = "Licensed";
            }
            else
            {
                licenseType = $"Evaluation (Expires {license.Expires.ToShortDateString()})";
            }

            ProductInformation = $"ComponentSpace.OpenID, Version={license.Version}, {licenseType}";
        }

        public string ProductInformation { get; set; }
    }
}
