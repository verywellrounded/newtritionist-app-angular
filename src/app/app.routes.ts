import { Routes } from '@angular/router';

import { AppComponent } from './app.component';
import { AuthComponent } from './components/auth/auth.component';
import { HomeComponent } from './components/home/home.component';
import { FoodInventoryComponent } from './components/food-inventory/food-inventory.component';
import { LayoutComponent } from './components/layout/layout.component';
import { ScanComponent } from './components/scan/scan.component';

/*
 * When it fails to find a route it redirects and then the page loads only one component. Why ?
 */
export const routes: Routes = [
  {
    title: 'Layout container',
    path: 'home',
    component: LayoutComponent,
    children: [
      {
        title: 'Food Inventory page',
        path: 'food-bank',
        component: FoodInventoryComponent,
      },
      {
        title: 'Scan page',
        path: 'scan',
        component: ScanComponent,
      },
      {
        title: 'Home page',
        path: 'home',
        component: HomeComponent,
      },
    ],
  },
  {
    title: 'Login page',
    path: 'login',
    loadComponent: () =>
      import('./components/auth/auth.component').then((c) => c.AuthComponent),
  },
  {
    title: 'Redirect to home',
    path: '',
    redirectTo: 'home',
    pathMatch: 'full',
  },
];
