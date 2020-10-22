using Farmizo.Web.Shopping.HttpAggregator.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Farmizo.Web.Shopping.HttpAggregator.Services
{
    public interface ICatalogService
    {
        Task<CatalogItem> GetCatalogItemAsync(int id);

        Task<IEnumerable<CatalogItem>> GetCatalogItemsAsync(IEnumerable<int> ids);
    }
}
