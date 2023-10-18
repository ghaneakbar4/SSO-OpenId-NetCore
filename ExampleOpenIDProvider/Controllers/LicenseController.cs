using ComponentSpace.OpenID.Utility;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web.Resource;

namespace ExampleOpenIDProvider.Controllers
{
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/[controller]")]
    [ApiController]
    public class LicenseController : ControllerBase
    {
        public const string GetLicenseScope = "license:get";

        public class LicenseInformation
        {
            public string? Name { get; set; }
            public string? Version { get; set; }
            public bool IsLicensed { get; set; }
            public DateTime Expires { get; set; }
            public string? DisplayMessage { get; set; }
        }

        private readonly ILicense _license;

        public LicenseController(ILicense license)
        {
            _license = license;
        }

        [HttpGet]
        [RequiredScope(GetLicenseScope)]
        public ActionResult<LicenseInformation> Get()
        {
            return new LicenseInformation()
            {
                Name = _license.Name,
                Version = _license.Version?.ToString(),
                IsLicensed = _license.IsLicensed,
                Expires = _license.Expires,
                DisplayMessage = GetDisplayMessage()
            };
        }

        private string GetDisplayMessage()
        {
            string licenseType;

            if (_license.IsLicensed)
            {
                licenseType = "Licensed";
            }
            else
            {
                licenseType = $"Evaluation (Expires {_license.Expires.ToShortDateString()})";
            }

            return $"ComponentSpace.OpenID, Version={_license.Version}, {licenseType}";
        }
    }
}
