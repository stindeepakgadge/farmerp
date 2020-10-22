using Microsoft.AspNetCore.Mvc;

namespace Farmizo.Web.Shopping.HttpAggregator.Controllers
{
    [Route("")]
    public class HomeController : Controller
    {
        [HttpGet()]
        public IActionResult Index()
        {
            return new RedirectResult("~/swagger");
        }
    }
}
