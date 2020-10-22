#pragma checksum "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "35fb83c1dba9efc403d2c3645f674560069a1547"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Order__OrderItems), @"mvc.1.0.view", @"/Views/Order/_OrderItems.cshtml")]
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
#nullable restore
#line 1 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\_ViewImports.cshtml"
using Farmizo.WebMVC;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\_ViewImports.cshtml"
using Farmizo.WebMVC.ViewModels;

#line default
#line hidden
#nullable disable
#nullable restore
#line 3 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\_ViewImports.cshtml"
using Microsoft.AspNetCore.Identity;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"35fb83c1dba9efc403d2c3645f674560069a1547", @"/Views/Order/_OrderItems.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"1d64c9e8a6fa9f02e6cf7443dd626188c6f3b453", @"/Views/_ViewImports.cshtml")]
    public class Views_Order__OrderItems : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<Farmizo.WebMVC.ViewModels.Order>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\r\n\r\n<section class=\"esh-orders_new-section\">\r\n    <article class=\"esh-orders_new-titles row\">\r\n        <section class=\"esh-orders_new-title col-12\">Order details</section>\r\n    </article>\r\n\r\n");
#nullable restore
#line 9 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
     for (int i = 0; i < Model.OrderItems.Count; i++)
    {
        var item = Model.OrderItems[i];


#line default
#line hidden
#nullable disable
            WriteLiteral("        <article class=\"esh-orders_new-items esh-orders_new-items--border row\">\r\n            <section class=\"esh-orders_new-item col-md-4 hidden-md-down\">\r\n                <img class=\"esh-orders_new-image\"");
            BeginWriteAttribute("src", " src=\"", 541, "\"", 563, 1);
#nullable restore
#line 15 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
WriteAttributeValue("", 547, item.PictureUrl, 547, 16, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(">\r\n                <input type=\"hidden\"");
            BeginWriteAttribute("value", " value=\"", 603, "\"", 627, 1);
#nullable restore
#line 16 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
WriteAttributeValue("", 611, item.PictureUrl, 611, 16, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            BeginWriteAttribute("name", " name=", 628, "", 671, 1);
#nullable restore
#line 16 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
WriteAttributeValue("", 634, "orderitems[" + i + "].PictureUrl", 634, 37, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(" />\r\n            </section>\r\n            <section class=\"esh-orders_new-item esh-orders_new-item--middle col-4\">\r\n                ");
#nullable restore
#line 19 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
           Write(item.ProductName);

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n                <input type=\"hidden\"");
            BeginWriteAttribute("value", " value=\"", 856, "\"", 881, 1);
#nullable restore
#line 20 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
WriteAttributeValue("", 864, item.ProductName, 864, 17, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            BeginWriteAttribute("name", " name=", 882, "", 926, 1);
#nullable restore
#line 20 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
WriteAttributeValue("", 888, "orderitems[" + i + "].ProductName", 888, 38, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(" />\r\n            </section>\r\n            <section class=\"esh-orders_new-item esh-orders_new-item--middle col-1\">\r\n                $ ");
#nullable restore
#line 23 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
             Write(item.UnitPrice.ToString("N2"));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n                <input type=\"hidden\"");
            BeginWriteAttribute("value", " value=\"", 1126, "\"", 1149, 1);
#nullable restore
#line 24 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
WriteAttributeValue("", 1134, item.UnitPrice, 1134, 15, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            BeginWriteAttribute("name", " name=", 1150, "", 1192, 1);
#nullable restore
#line 24 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
WriteAttributeValue("", 1156, "orderitems[" + i + "].UnitPrice", 1156, 36, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(" />\r\n            </section>\r\n            <section class=\"esh-orders_new-item esh-orders_new-item--middle col-1\">\r\n                ");
#nullable restore
#line 27 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
           Write(item.Units);

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n                <input type=\"hidden\"");
            BeginWriteAttribute("value", " value=\"", 1371, "\"", 1390, 1);
#nullable restore
#line 28 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
WriteAttributeValue("", 1379, item.Units, 1379, 11, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            BeginWriteAttribute("name", " name=", 1391, "", 1429, 1);
#nullable restore
#line 28 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
WriteAttributeValue("", 1397, "orderitems[" + i + "].Units", 1397, 32, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(" />\r\n            </section>\r\n            <section class=\"esh-orders_new-item esh-orders_new-item--middle col-2\">$ ");
#nullable restore
#line 30 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
                                                                                Write(Math.Round(item.Units * item.UnitPrice, 2).ToString("N2"));

#line default
#line hidden
#nullable disable
            WriteLiteral("</section>\r\n        </article>\r\n");
#nullable restore
#line 32 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
    }

#line default
#line hidden
#nullable disable
            WriteLiteral(@"</section>

<section class=""esh-orders_new-section esh-orders_new-section--right"">
    <article class=""esh-orders_new-titles row"">
        <section class=""esh-orders_new-title col-9""></section>
        <section class=""esh-orders_new-title col-2"">Total</section>
    </article>

    <article class=""esh-orders_new-items row"">
        <section class=""esh-orders_new-item col-9""></section>
        <section class=""esh-orders_new-item esh-orders_new-item--mark col-2"">
            $ ");
#nullable restore
#line 44 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
         Write(Model.Total.ToString("N2"));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n            <input type=\"hidden\"");
            BeginWriteAttribute("value", " value=\"", 2191, "\"", 2211, 1);
#nullable restore
#line 45 "D:\Deepak Working Directory\Farmizo_Cloud\Farmizo\src\Web\WebMVC\Views\Order\_OrderItems.cshtml"
WriteAttributeValue("", 2199, Model.Total, 2199, 12, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(" name=\"Total\"/>\r\n        </section>\r\n    </article>\r\n</section>\r\n");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<Farmizo.WebMVC.ViewModels.Order> Html { get; private set; }
    }
}
#pragma warning restore 1591