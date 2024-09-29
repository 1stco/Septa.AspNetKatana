// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Owin.Security.OpenIdConnect;
using System;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="SeptaOpenIdConnectAuthenticationExtensions"/>
    /// </summary>
    public static class SeptaOpenIdConnectAuthenticationExtensions
    {
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