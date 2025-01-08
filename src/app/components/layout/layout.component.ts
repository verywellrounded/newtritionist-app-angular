import { Component, Input } from '@angular/core';
import { NavComponent } from '../nav/nav.component';
import { CommonModule } from '@angular/common';
import { HomeComponent } from '../home/home.component';

@Component({
  selector: 'app-layout',
  imports: [NavComponent, CommonModule, HomeComponent],
  template: `
    <div class="layoutContainer">
      <!-- <link rel="manifest" href="/manifest.json"></link> -->
      <ng-content>
        <app-home style="border: 1px solid #ddd;"></app-home>
        @if(displayNavBar){
        <app-nav [class]="navClassName"></app-nav>
        }
      </ng-content>
    </div>
  `,
  styleUrl: './layout.component.css',
})
export class LayoutComponent {
  @Input() displayNavBar: boolean = true;
  @Input() navClassName: string = 'navContainer';
}
