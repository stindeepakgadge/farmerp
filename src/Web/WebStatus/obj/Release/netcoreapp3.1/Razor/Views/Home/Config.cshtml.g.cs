#pragma checksum "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebStatus\Views\Home\Config.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "78a26ceea5b2a64b960476c7d20b32becb94bd7f"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Home_Config), @"mvc.1.0.view", @"/Views/Home/Config.cshtml")]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"78a26ceea5b2a64b960476c7d20b32becb94bd7f", @"/Views/Home/Config.cshtml")]
    public class Views_Home_Config : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<Dictionary<string, string>>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\r\n");
#nullable restore
#line 3 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebStatus\Views\Home\Config.cshtml"
  
    ViewData["Title"] = "WebStatus Configuration";

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n<h1>Configuration Values</h1>\r\n\r\n<table>\r\n");
#nullable restore
#line 10 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebStatus\Views\Home\Config.cshtml"
     foreach (var item in Model)
    {

#line default
#line hidden
#nullable disable
            WriteLiteral("        <tr>\r\n            <td>");
#nullable restore
#line 13 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebStatus\Views\Home\Config.cshtml"
           Write(item.Key);

#line default
#line hidden
#nullable disable
            WriteLiteral("</td>\r\n            <td>");
#nullable restore
#line 14 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebStatus\Views\Home\Config.cshtml"
           Write(item.Value);

#line default
#line hidden
#nullable disable
            WriteLiteral("</td>\r\n        </tr>\r\n");
#nullable restore
#line 16 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebStatus\Views\Home\Config.cshtml"
    }

#line default
#line hidden
#nullable disable
            WriteLiteral("</table>\r\n");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<Dictionary<string, string>> Html { get; private set; }
    }
}
#pragma warning restore 1591
