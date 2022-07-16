// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.Owin.Security.OpenIdConnect;

namespace Owin
{
    public static class SeptaOpenIdConnectAuthenticationExtensions
    {
        /// <summary>
        /// Adds the <see cref="SeptaOpenIdConnectAuthenticationMiddleware"/> into the OWIN runtime.
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="optionsKeyFunc">Func that resolves Key for Configuration options for the middleware</param>
        /// <param name="optionsFunc">Func that resolves Configuration options for the middleware</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseSeptaOpenIdConnectAuthentication(this IAppBuilder app, Func<string> optionsKeyFunc, Func<string, OpenIdConnectAuthenticationOptions> optionsFunc)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            if (optionsKeyFunc == null)
            {
                throw new ArgumentNullException("optionsKeyFunc");
            }

            if (optionsFunc == null)
            {
                throw new ArgumentNullException("optionsFunc");
            }
            return app.Use(typeof(SeptaOpenIdConnectAuthenticationMiddleware), app, optionsKeyFunc, optionsFunc);
        }

    }
}