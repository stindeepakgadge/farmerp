#pragma checksum "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "4da11bce60bd2296d2a4f57d97bf8ad034bae22b"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Consent__ScopeListItem), @"mvc.1.0.view", @"/Views/Consent/_ScopeListItem.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"4da11bce60bd2296d2a4f57d97bf8ad034bae22b", @"/Views/Consent/_ScopeListItem.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"23ac09be4bcfaa7f9829a01d1a134874eaae1f3b", @"/Views/_ViewImports.cshtml")]
    public class Views_Consent__ScopeListItem : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<Farmizo.Services.Identity.API.Models.AccountViewModels.ScopeViewModel>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\r\n<li class=\"list-group-item\">\r\n    <label>\r\n        <input class=\"consent-scopecheck\"\r\n               type=\"checkbox\"\r\n               name=\"ScopesConsented\"");
            BeginWriteAttribute("id", "\r\n               id=\"", 236, "\"", 275, 2);
            WriteAttributeValue("", 257, "scopes_", 257, 7, true);
#nullable restore
#line 8 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
WriteAttributeValue("", 264, Model.Name, 264, 11, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            BeginWriteAttribute("value", "\r\n               value=\"", 276, "\"", 311, 1);
#nullable restore
#line 9 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
WriteAttributeValue("", 300, Model.Name, 300, 11, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            BeginWriteAttribute("checked", "\r\n               checked=\"", 312, "\"", 352, 1);
#nullable restore
#line 10 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
WriteAttributeValue("", 338, Model.Checked, 338, 14, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            BeginWriteAttribute("disabled", "\r\n               disabled=\"", 353, "\"", 395, 1);
#nullable restore
#line 11 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
WriteAttributeValue("", 380, Model.Required, 380, 15, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(" />\r\n");
#nullable restore
#line 12 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
         if (Model.Required)
        {

#line default
#line hidden
#nullable disable
            WriteLiteral("            <input type=\"hidden\"\r\n                   name=\"ScopesConsented\"");
            BeginWriteAttribute("value", "\r\n                   value=\"", 517, "\"", 556, 1);
#nullable restore
#line 16 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
WriteAttributeValue("", 545, Model.Name, 545, 11, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(" />\r\n");
#nullable restore
#line 17 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
        }

#line default
#line hidden
#nullable disable
            WriteLiteral("        <strong>");
#nullable restore
#line 18 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
           Write(Model.DisplayName);

#line default
#line hidden
#nullable disable
            WriteLiteral("</strong>\r\n");
#nullable restore
#line 19 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
         if (Model.Emphasize)
        {

#line default
#line hidden
#nullable disable
            WriteLiteral("            <span class=\"glyphicon glyphicon-exclamation-sign\"></span>\r\n");
#nullable restore
#line 22 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
        }

#line default
#line hidden
#nullable disable
            WriteLiteral("    </label>\r\n");
#nullable restore
#line 24 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
     if (Model.Required)
    {

#line default
#line hidden
#nullable disable
            WriteLiteral("        <span><em>(required)</em></span>\r\n");
#nullable restore
#line 27 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
    }

#line default
#line hidden
#nullable disable
#nullable restore
#line 28 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
     if (Model.Description != null)
    {

#line default
#line hidden
#nullable disable
            WriteLiteral("        <div class=\"consent-description\">\r\n            <label");
            BeginWriteAttribute("for", " for=\"", 944, "\"", 968, 2);
            WriteAttributeValue("", 950, "scopes_", 950, 7, true);
#nullable restore
#line 31 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
WriteAttributeValue("", 957, Model.Name, 957, 11, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(">");
#nullable restore
#line 31 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
                                       Write(Model.Description);

#line default
#line hidden
#nullable disable
            WriteLiteral("</label>\r\n        </div>\r\n");
#nullable restore
#line 33 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Services\Identity\Identity.API\Views\Consent\_ScopeListItem.cshtml"
    }

#line default
#line hidden
#nullable disable
            WriteLiteral("</li>");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<Farmizo.Services.Identity.API.Models.AccountViewModels.ScopeViewModel> Html { get; private set; }
    }
}
#pragma warning restore 1591
