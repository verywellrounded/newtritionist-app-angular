import { Routes } from '@angular/router';
import { AuthComponent } from '../auth/auth.component';
import { AppComponent } from './app.component';

/*
 * When it fails to find a route it redirects and then the page loads only one component. Why ?
 */
export const routes: Routes = [
  {
    title: 'Default',
    path: '',
    redirectTo: '/home',
    pathMatch: 'full',
  },
  {
    title: '',
    path: 'home',
    component: AppComponent,
  },
  {
    title: '',
    path: 'login',
    component: AuthComponent,
  },
];
