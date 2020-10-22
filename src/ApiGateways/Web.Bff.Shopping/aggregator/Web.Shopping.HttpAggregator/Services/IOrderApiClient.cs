using Farmizo.Web.Shopping.HttpAggregator.Models;
using System.Threading.Tasks;

namespace Farmizo.Web.Shopping.HttpAggregator.Services
{
    public interface IOrderApiClient
    {
        Task<OrderData> GetOrderDraftFromBasketAsync(BasketData basket);
    }
}
