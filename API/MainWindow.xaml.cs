using System.IO;
using System.Net;
using System.Text;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

using System.Net.Http;
using Newtonsoft.Json;
using System.Threading.Tasks;

using API.Model;

namespace API
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        SpotifyToken spotifyToken;
        public MainWindow()
        {
            InitializeComponent();

          string token =  GetAccessToken();

            GetArtist(token);
        }


        private const string ClientId = "<your_client_id>";
        private const string ClientSecret = "<your_client_secret>";
        private const string RedirectUri = "http://localhost:5000/callback";

        [HttpGet("callback")]
        public async Task<IActionResult> Callback(string code)
        {
            if (string.IsNullOrEmpty(code))
            {
                return BadRequest("Authorization code is missing");
            }

            using (HttpClient client = new HttpClient())
            {
                var requestBody = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", RedirectUri),
                new KeyValuePair<string, string>("client_id", ClientId),
                new KeyValuePair<string, string>("client_secret", ClientSecret)
            });

                HttpResponseMessage response = await client.PostAsync("https://accounts.spotify.com/api/token", requestBody);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var tokenResponse = JsonConvert.DeserializeObject<TokenResponse>(content);
                    return Ok(tokenResponse); // Contains access_token, refresh_token, etc.
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return BadRequest($"Token exchange failed: {errorContent}");
                }
            }
        }

        public string GetAccessToken()
        {
        
            string url5 = "https://accounts.spotify.com/api/token";
            var clientid = "2676faaf7183470aaf881a6b70c456d3";
            var clientsecret = "90d3382359ce4b0eb4f3fa8f7de06b2a";

            //request to get the access token
            var encode_clientid_clientsecret = Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Format("{0}:{1}", clientid, clientsecret)));

            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(url5);

            webRequest.Method = "POST";
            webRequest.ContentType = "application/x-www-form-urlencoded";
            webRequest.Accept = "application/json";
            webRequest.Headers.Add("Authorization: Basic " + encode_clientid_clientsecret);

            var request = ("grant_type=client_credentials");
            byte[] req_bytes = Encoding.ASCII.GetBytes(request);
            webRequest.ContentLength = req_bytes.Length;

            Stream strm = webRequest.GetRequestStream();
            strm.Write(req_bytes, 0, req_bytes.Length);
            strm.Close();

            HttpWebResponse resp = (HttpWebResponse)webRequest.GetResponse();
       
            using (Stream respStr = resp.GetResponseStream())
            {
                using (StreamReader rdr = new StreamReader(respStr, Encoding.UTF8))
                {
                    //should get back a string i can then turn to json and parse for accesstoken
                    var json = rdr.ReadToEnd();
                    spotifyToken = JsonConvert.DeserializeObject<SpotifyToken>(json);

                    rdr.Close();
                }
            }
            return spotifyToken.access_token;
        }


        public async Task<string> GetArtist(string token)
        {
            // Create an HttpClient instance
            using (HttpClient client = new HttpClient())
            {
                // Add the Authorization header with the Bearer token
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

                // Make the GET request
                HttpResponseMessage response = await client.GetAsync("https://api.spotify.com/v1/artists");

                // Check if the response is successful
                if (response.IsSuccessStatusCode)
                {
                    // Read and return the content
                    var content = await response.Content.ReadAsStringAsync();

                    // Optionally deserialize the JSON into a Root object if necessary
                    var data = JsonConvert.DeserializeObject<Root>(content);

                    return content;
                }

                // Return null or handle errors appropriately
                return null;
            }
        }




        public class TokenResponse
        {
            [JsonProperty("access_token")]
            public string AccessToken { get; set; }

            [JsonProperty("token_type")]
            public string TokenType { get; set; }

            [JsonProperty("expires_in")]
            public int ExpiresIn { get; set; }

            [JsonProperty("refresh_token")]
            public string RefreshToken { get; set; }

            [JsonProperty("scope")]
            public string Scope { get; set; }
        }


    }

}