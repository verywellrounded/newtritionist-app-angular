import { Routes } from '@angular/router';

import { AppComponent } from './app.component';
import { AuthComponent } from './components/auth/auth.component';
import { HomeComponent } from './components/home/home.component';
import { FoodInventoryComponent } from './components/food-inventory/food-inventory.component';
import { LayoutComponent } from './components/layout/layout.component';
import { ScanComponent } from './components/scan/scan.component';
import { authGuardGuard } from './auth-guard.guard';

/*
 * When it fails to find a route it redirects and then the page loads only one component. Why ?
 */
export const routes: Routes = [
  {
    title: 'root',
    path: '',
    children: [
      {
        path: '',
        title: 'Redirect to home page',
        pathMatch: 'full',
        redirectTo: 'home',
      },
      {
        title: 'Layout container',
        path: 'home',
        component: LayoutComponent, // probably should use this in each component instead of routing directly to it
        canActivate: [authGuardGuard],
      },
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
        title: 'Login page',
        path: 'login',
        component: AuthComponent,
      },
    ],
  },
  { title: 'Catch all', path: '**', redirectTo: 'home', pathMatch: 'full' }, // update this to redirect to 404 page
];
