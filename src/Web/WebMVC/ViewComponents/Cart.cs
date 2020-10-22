﻿using Microsoft.AspNetCore.Mvc;
using Farmizo.WebMVC.ViewModels;
using Farmizo.WebMVC.ViewModels.CartViewModels;
using Farmizo.WebMVC.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Farmizo.WebMVC.ViewComponents
{
    public class Cart : ViewComponent
    {
        private readonly IBasketService _cartSvc;

        public Cart(IBasketService cartSvc) => _cartSvc = cartSvc;

        public async Task<IViewComponentResult> InvokeAsync(ApplicationUser user)
        {
            var vm = new CartComponentViewModel();
            try
            {
                var itemsInCart = await ItemsInCartAsync(user);
                vm.ItemsCount = itemsInCart;
                return View(vm);
            }
            catch 
            {
                ViewBag.IsBasketInoperative = true;
            }

            return View(vm);
        }
        private async Task<int> ItemsInCartAsync(ApplicationUser user)
        {
            var basket = await _cartSvc.GetBasket(user);
            return basket.Items.Count;
        }
    }
}