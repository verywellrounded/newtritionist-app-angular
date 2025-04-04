import { Component, Input } from '@angular/core';
import { NavComponent } from '../nav/nav.component';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-layout',
  imports: [NavComponent, CommonModule],
  template: `
    <div class="layoutContainer">
      <!-- <link rel="manifest" href="/manifest.json"></link> -->
      <ng-content></ng-content>
      <!-- Allows the child content to be projected here Any content inside 
       <app-layout> in the child component will be projected into the <ng-content> tag--->
      @if(displayNavBar){
      <app-nav></app-nav>
      }
    </div>
  `,
  styleUrl: './layout.component.css',
})
export class LayoutComponent {
  @Input() displayNavBar: boolean = true;
  @Input() navClassName: string = 'navContainer';
}
