// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace Microsoft.Owin.Security.OpenIdConnect
{
    public class SeptaOpenIdConnectAuthenticationMiddleware : AuthenticationMiddleware<OpenIdConnectAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly ConcurrentDictionary<string, OpenIdConnectAuthenticationOptions> _optionsDic = new ConcurrentDictionary<string, OpenIdConnectAuthenticationOptions>();
        private readonly Func<string> _optionsKeyFunc;
        private readonly Func<string, OpenIdConnectAuthenticationOptions> _optionsFunc;
        private readonly string _authenticationType;
        private readonly IDataProtector _dataProtector;

        /// <summary>
        /// Initializes a <see cref="OpenIdConnectAuthenticationMiddleware"/>
        /// </summary>
        /// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
        /// <param name="app">The OWIN application</param>
        /// <param name="optionsKeyFunc">Func that resolves Key for Configuration options for the middleware</param>
        /// <param name="optionsFunc">Func that resolves Configuration options for the middleware</param>
        [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Managed by caller")]
        public SeptaOpenIdConnectAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, Func<string> optionsKeyFunc, Func<string, OpenIdConnectAuthenticationOptions> optionsFunc)
            : base(next, null)
        {
            _logger = app.CreateLogger<OpenIdConnectAuthenticationMiddleware>();
            _optionsKeyFunc = optionsKeyFunc;
            _optionsFunc = optionsFunc;

            _authenticationType = app.GetDefaultSignInAsAuthenticationType();
            _dataProtector = app.CreateDataProtector(
                    typeof(OpenIdConnectAuthenticationMiddleware).FullName,
                   _authenticationType, "v1");
        }

        public override OpenIdConnectAuthenticationOptions Options
        {
            get
            {
                return _optionsDic.GetOrAdd(_optionsKeyFunc(), k => BuildOptions(k));
            }
        }

        private OpenIdConnectAuthenticationOptions BuildOptions(string key)
        {
            var toReturn = _optionsFunc(key);
            if (string.IsNullOrWhiteSpace(toReturn.TokenValidationParameters.AuthenticationType))
            {
                toReturn.TokenValidationParameters.AuthenticationType = _authenticationType;
            }

            if (toReturn.StateDataFormat == null)
            {               
                toReturn.StateDataFormat = new PropertiesDataFormat(_dataProtector);
            }

            // if the user has not set the AuthorizeCallback, set it from the redirect_uri
            if (!toReturn.CallbackPath.HasValue)
            {
                Uri redirectUri;
                if (!string.IsNullOrEmpty(toReturn.RedirectUri) && Uri.TryCreate(toReturn.RedirectUri, UriKind.Absolute, out redirectUri))
                {
                    // Redirect_Uri must be a very specific, case sensitive value, so we can't generate it. Instead we generate AuthorizeCallback from it.
                    toReturn.CallbackPath = PathString.FromUriComponent(redirectUri);
                }
            }

            if (toReturn.Notifications == null)
            {
                toReturn.Notifications = new OpenIdConnectAuthenticationNotifications();
            }

            if (string.IsNullOrWhiteSpace(toReturn.TokenValidationParameters.ValidAudience) && !string.IsNullOrWhiteSpace(toReturn.ClientId))
            {
                toReturn.TokenValidationParameters.ValidAudience = toReturn.ClientId;
            }

            if (toReturn.Backchannel == null)
            {
                toReturn.Backchannel = new HttpClient(ResolveHttpMessageHandler(toReturn));
                toReturn.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft ASP.NET Core OpenIdConnect middleware");
                toReturn.Backchannel.Timeout = toReturn.BackchannelTimeout;
                toReturn.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
            }

            if (toReturn.ConfigurationManager == null)
            {
                if (toReturn.Configuration != null)
                {
                    toReturn.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(toReturn.Configuration);
                }
                else if (!(string.IsNullOrEmpty(toReturn.MetadataAddress) && string.IsNullOrEmpty(toReturn.Authority)))
                {
                    if (string.IsNullOrEmpty(toReturn.MetadataAddress) && !string.IsNullOrEmpty(toReturn.Authority))
                    {
                        toReturn.MetadataAddress = toReturn.Authority;
                        if (!toReturn.MetadataAddress.EndsWith("/", StringComparison.Ordinal))
                        {
                            toReturn.MetadataAddress += "/";
                        }

                        toReturn.MetadataAddress += ".well-known/openid-configuration";
                    }

                    if (toReturn.RequireHttpsMetadata && !toReturn.MetadataAddress.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("The MetadataAddress or Authority must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.");
                    }

                    toReturn.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(toReturn.MetadataAddress, new OpenIdConnectConfigurationRetriever(),
                        new HttpDocumentRetriever(toReturn.Backchannel) { RequireHttps = toReturn.RequireHttpsMetadata });
                }
            }

            if (toReturn.ConfigurationManager == null)
            {
                throw new InvalidOperationException("Provide Authority, MetadataAddress, Configuration, or ConfigurationManager to OpenIdConnectAuthenticationOptions");
            }

            return toReturn;
        }

        /// <summary>
        /// Provides the <see cref="AuthenticationHandler"/> object for processing authentication-related requests.
        /// </summary>
        /// <returns>An <see cref="AuthenticationHandler"/> configured with the <see cref="OpenIdConnectAuthenticationOptions"/> supplied to the constructor.</returns>
        protected override AuthenticationHandler<OpenIdConnectAuthenticationOptions> CreateHandler()
        {
            return new OpenIdConnectAuthenticationHandler(_logger);
        }

        [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Managed by caller")]
        private static HttpMessageHandler ResolveHttpMessageHandler(OpenIdConnectAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
                }

                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }
    }


}
