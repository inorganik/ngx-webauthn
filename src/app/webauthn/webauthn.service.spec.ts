import { TestBed } from '@angular/core/testing';

import { WebauthnService } from './webauthn.service';

describe('WebauthnService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: WebauthnService = TestBed.get(WebauthnService);
    expect(service).toBeTruthy();
  });
});
