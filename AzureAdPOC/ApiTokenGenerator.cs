using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

public static class ApiTokenGenerator
{
    public static async Task<string> GetTokenFromApi(string apiUrl, object requestData)
    {
        try
        {
            Console.WriteLine($"In APITOKENGENERATOR : GetTokenFromAPI request to {apiUrl}");
            using var httpClient = new HttpClient();
            var response = await httpClient.PostAsJsonAsync(apiUrl, requestData);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"API Response: {responseContent}");
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent);
                return tokenResponse?.Token;
            }
            else
            {
                Console.WriteLine("APIReq failed");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error getting token from API: {ex.Message}");
        }
        Console.WriteLine("Returning null");
        return null;
    }

    private class TokenResponse
    {
        [JsonPropertyName("token")]
        public string Token { get; set; }
    }
}