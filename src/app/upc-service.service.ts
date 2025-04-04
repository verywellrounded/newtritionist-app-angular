import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root',
})
export class UpcService {
  httpClient = inject(HttpClient);
  readonly baseUrl = 'https://api.zebra.com/v2/tools/barcode/lookup?upc=';

  constructor() {}
  upcLookUp(upc: string) {
    console.log('looking up', upc);
    return this.httpClient.get(`${this.baseUrl}${upc}`, {
      headers: {
        accept: 'application/json',
        apikey: 'aynD4nrqxizADADOlc98siT1c6ArxwVH',
      },
    });
  }
}
