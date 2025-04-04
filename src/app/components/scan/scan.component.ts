import {
  afterRender,
  Component,
  inject,
  PLATFORM_ID,
  signal,
} from '@angular/core';
import { Html5QrcodeScanner } from 'html5-qrcode';
import { UpcService } from '../../upc-service.service';
import { isPlatformBrowser } from '@angular/common';
import { LayoutComponent } from '../layout/layout.component';

@Component({
  selector: 'app-scan',
  imports: [LayoutComponent],
  templateUrl: './scan.component.html',
  styleUrl: './scan.component.css',
})
export class ScanComponent {
  currentScannedItem = signal<string>('');
  scanningToggle = signal<boolean>(true);

  html5QrcodeScanner: Html5QrcodeScanner | null = null;
  upcService = inject(UpcService);
  platformId = inject(PLATFORM_ID);

  constructor() {
    afterRender(() => {});
  }

  ngAfterViewInit() {
    const onScanSuccess = (decodedText: string, decodedResult: any) => {
      //TODO: pick up here to flash the scabbed item , beep, preview or quick accept and quantity and move on
      // add the scanned item to the list
      // handle the scanned code as you like, for example:
      console.log(`Code matched = ${decodedText}`, decodedResult);
      this.currentScannedItem.set(JSON.stringify(decodedResult));
      // this.scanningToggle.set(false);
      this.upcService.upcLookUp(decodedText).subscribe({
        next: (data) => {
          // figure out how to flash the scanned item
          console.log(data);
          // this.scanningToggle.set(true);
        },
        error: (error) => {
          // save this upc code to try again when user finish scannings
          console.log(error);
          // this.scanningToggle.set(true);
        },
        complete: () => {
          console.log('complete');
        },
      });
    };
    const onScanFailure = (error: any) => {
      // handle scan failure, usually better to ignore and keep scanning.
      // visually indicate error allow user to try again
      // console.warn(`Code scan error = ${error}`);
    };
    if (isPlatformBrowser(this.platformId)) {
      this.html5QrcodeScanner = new Html5QrcodeScanner(
        'reader',
        { fps: 10, qrbox: { width: 500, height: 500 } },
        /* verbose= */ false
      );
      this.html5QrcodeScanner.render(onScanSuccess, onScanFailure);
    }
  }

  ngAfterSignalUpdate(): void {
    // if (this.scanningToggle()) {
    //   this.html5QrcodeScanner?.pause();
    // } else {
    //   this.html5QrcodeScanner?.resume();
    // }
  }
  // // onclick request to open the camera and scan a barcode
  // scan() {
  //   //     preferFrontCamera: false, // iOS and Android
  //   //     showFlipCameraButton: true, // iOS and Android
  //   //     showTorchButton: true, // iOS and Android
  //   //     showCancelButton: true, // iOS
  //   //     showPreview: false, // Android
  //   `https://api.zebra.com/v2/tools/barcode/lookup?upc=${upc}`,
  //     console.log('Scanning...');
  //   // Implement your scanning logic here
  // }
}
