using System.ComponentModel.DataAnnotations.Schema;

namespace ExampleOpenIDProvider.Data
{
    public class OpenIDUser
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string? Id { get; set; }

        public string? RefreshToken { get; set; }

        public string? ClientID { get; set; }

        public string? Subject { get; set; }

        public DateTime? UtcExpiresAt { get; set; }
    }
}
