﻿using Microsoft.AspNetCore.Mvc.Rendering;
using Farmizo.WebMVC.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Farmizo.WebMVC.Services
{
    public interface ICatalogService
    {
        Task<Catalog> GetCatalogItems(int page, int take, int? brand, int? type);
        Task<IEnumerable<SelectListItem>> GetBrands();
        Task<IEnumerable<SelectListItem>> GetTypes();
    }
}
