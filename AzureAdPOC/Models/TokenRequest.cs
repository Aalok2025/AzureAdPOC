﻿namespace AzureAdPOC.Models
{
    public class TokenRequest
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }
    }
}
