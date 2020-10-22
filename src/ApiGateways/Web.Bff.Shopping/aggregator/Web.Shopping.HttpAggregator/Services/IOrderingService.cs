using Farmizo.Web.Shopping.HttpAggregator.Models;
using System.Threading.Tasks;

namespace Farmizo.Web.Shopping.HttpAggregator.Services
{
    public interface IOrderingService
    {
        Task<OrderData> GetOrderDraftAsync(BasketData basketData);
    }
}