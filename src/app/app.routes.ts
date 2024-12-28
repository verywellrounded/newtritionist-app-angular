import { Routes } from '@angular/router';

import { AppComponent } from './app.component';
import { AuthComponent } from '../auth/auth.component';
import { HomeComponent } from './components/home/home.component';

/*
 * When it fails to find a route it redirects and then the page loads only one component. Why ?
 */
export const routes: Routes = [
  {
    title: 'Login page',
    path: 'login',
    component: AuthComponent,
  },
  {
    title: 'Home page',
    path: 'home',
    component: HomeComponent,
  },
  {
    title: 'Redirect to home',
    path: '',
    redirectTo: 'home',
    pathMatch: 'full',
  },
];
