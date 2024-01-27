    class ProtectimusApiService
    {
        private const string API_V1_AUTH_PATH = "api/v1/auth-service";

        internal ProtectimusApiResponse<LogicalResult> AuthUserToken(UserIdentityData user, string otp)
        {
            var url = string.Format("{0}/{1}/authenticate/user-token.json", Configuration.Current.ApiUrl, API_V1_AUTH_PATH);
            var authValue = Encoding.ASCII.GetBytes($"{Configuration.Current.Login}:{GetApiAuthHashValue()}");

            var formContent = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "resourceId", Configuration.Current.ResourceId },
                { "userLogin", GetUserName(user) },
                { "otp", otp }
            });

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(authValue));
                    var httpResponse = client.PostAsync(url, formContent).GetAwaiter().GetResult();

                    Stream responseStream = httpResponse.Content.ReadAsStreamAsync().GetAwaiter().GetResult();
                    DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(ProtectimusApiResponse<LogicalResult>));
                    var model = serializer.ReadObject(responseStream) as ProtectimusApiResponse<LogicalResult>;
                    return model;
                }
            }
            catch (Exception ex)
            {
                // Log Exception
                return null;
            }
        }

        // you need to call PrepareAuth method in case your users use tokens through the sms, email, etc.
        // you can call it always if you don't know which token type user uses
        internal ProtectimusApiResponse<PrepareAuthResponse> PrepareAuth(UserIdentityData user)
        {
            var url = string.Format("{0}/{1}/prepare.json", Configuration.Current.ApiUrl, API_V1_AUTH_PATH);
            var authValue = Encoding.ASCII.GetBytes($"{Configuration.Current.Login}:{GetApiAuthHashValue()}");

            var formContent = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "resourceId", Configuration.Current.ResourceId },
                { "userLogin", GetUserName(user) }
            });

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(authValue));
                    var httpResponse = client.PostAsync(url, formContent).GetAwaiter().GetResult();

                    DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(ProtectimusApiResponse<PrepareAuthResponse>));
                    var model = serializer.ReadObject(httpResponse.Content.ReadAsStreamAsync().GetAwaiter().GetResult()) as ProtectimusApiResponse<PrepareAuthResponse>;
                    return model;
                }
            }
            catch (Exception ex)
            {
                // Log Exception
                return null;
            }
        }

        private string GetApiAuthHashValue()
        {
            DateTime dateTimeNow = DateTime.UtcNow;
            string date = dateTimeNow.ToString("yyyyMMdd");
            string time = dateTimeNow.ToString("HH");
            string key = $"{Configuration.Current.ApiKey}:{date}:{time}";

            using (var sha = new System.Security.Cryptography.SHA256Managed())
            {
                byte[] textData = Encoding.UTF8.GetBytes(key);
                byte[] hash = sha.ComputeHash(textData);
                return BitConverter.ToString(hash).Replace("-", string.Empty);
            }
        }

        private string GetUserName(UserIdentityData user)
        {
            // make any changes to User name depending on your Active Directory
            // for example $"{user.Name}@{user.Domain}" or $"{user.Domain}\\{user.Name}" or just user.OriginalIdentityName
        }
    }

    class UserIdentityData
    {
        internal string OriginalIdentityName { get; set; }
        internal string Domain { get; set; }
        internal string Name { get; set; }
    }

    [DataContract]
    class ProtectimusApiResponse<T>
    {
        [DataMember(Name = "responseHolder")]
        internal ResponseHolder<T> ResponseHolder { get; set; }
    }

    [DataContract]
    class ResponseHolder<T>
    {
        [DataMember(Name = "response")]
        internal T Response { get; set; }

        [DataMember(Name = "error")]
        internal ApiError Error { get; set; }

        [DataMember(Name = "status")]
        internal string Status { get; set; }
    }

    [DataContract]
    class ApiError
    {
        [DataMember(Name = "code")]
        internal int Code { get; set; }

        [DataMember(Name = "message")]
        internal string Message { get; set; }

        [DataMember(Name = "developersMessage")]
        public string DevelopersMessage { get; set; }
    }

    [DataContract]
    class PrepareAuthResponse
    {
        [DataMember(Name = "challenge")]
        internal int? Challenge { get; set; }

        [DataMember(Name = "tokenName")]
        internal string TokenName { get; set; }

        [DataMember(Name = "tokenType")]
        internal string TokenType { get; set; }

        [DataMember(Name = "authId")]
        internal string AuthId { get; set; }
    }

    [DataContract]
    class LogicalResult
    {
        [DataMember(Name = "result")]
        internal bool Result { get; set; }
    }
