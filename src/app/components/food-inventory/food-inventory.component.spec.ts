import { ComponentFixture, TestBed } from '@angular/core/testing';

import { FoodInventoryComponent } from './food-inventory.component';

describe('FoodInventoryComponent', () => {
  let component: FoodInventoryComponent;
  let fixture: ComponentFixture<FoodInventoryComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [FoodInventoryComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(FoodInventoryComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
