using Farmizo.Web.Shopping.HttpAggregator.Models;
using System.Threading.Tasks;

namespace Farmizo.Web.Shopping.HttpAggregator.Services
{
    public interface IBasketService
    {
        Task<BasketData> GetById(string id);

        Task UpdateAsync(BasketData currentBasket);
    }
}
