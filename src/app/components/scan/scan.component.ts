import { AfterViewInit, Component, OnInit, signal } from '@angular/core';
import { Html5QrcodeScanner } from 'html5-qrcode';

@Component({
  selector: 'app-scan',
  imports: [],
  templateUrl: './scan.component.html',
  styleUrl: './scan.component.css',
})
export class ScanComponent implements AfterViewInit {
  currentScannedItem = signal<string>('');
  ngAfterViewInit() {
    const onScanSuccess = (decodedText: string, decodedResult: any) => {
      // handle the scanned code as you like, for example:

      console.log(`Code matched = ${decodedText}`, decodedResult);
      this.currentScannedItem.set(JSON.stringify(decodedResult));
    };

    const onScanFailure = (error: any) => {
      // handle scan failure, usually better to ignore and keep scanning.
      // for example:
      console.warn(`Code scan error = ${error}`);
    };

    let html5QrcodeScanner = new Html5QrcodeScanner(
      'reader',
      { fps: 10, qrbox: { width: 250, height: 250 } },
      /* verbose= */ false
    );
    html5QrcodeScanner.render(onScanSuccess, onScanFailure);
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
