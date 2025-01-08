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
  styleUrl: './nav.component.css',
})
export class NavComponent {
  @HostBinding('class.navContainer') isNavContainer = true;
  router: Router = inject(Router);
  @Input() className: string;

  constructor() {
    this.className = 'navContainer';
  }

  navigateTo(pageUrl: string) {
    console.log('Navigating to auth');
    this.router.navigate([`/${pageUrl}`]);
  }
}
