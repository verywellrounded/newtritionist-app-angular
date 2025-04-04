import { Component, HostBinding, inject, Input, input } from '@angular/core';
import { Router } from '@angular/router';
import { MatButton } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-nav',
  imports: [MatIconModule],
  template: `
    <button mat-mini-fab variant="contained" (click)="navigateTo('food-bank')">
      <mat-icon>Food Bank</mat-icon>
    </button>
    <Button mat-mini-fab variant="contained" (click)="navigateTo('scan')">
      <mat-icon>Scan</mat-icon>
    </Button>
    <Button mat-mini-fab variant="contained" (click)="navigateTo('explore')">
      <mat-icon>Explore</mat-icon>
    </Button>
  `,
})
export class NavComponent {
  // TODO: I dont like this way of setting className find a neater way
  @HostBinding('class.navContainer') isNavContainer = true;
  router: Router = inject(Router);

  constructor() {}

  navigateTo(pageUrl: string) {
    console.log('Navigating to auth');
    this.router.navigate([`/${pageUrl}`]);
  }
}
