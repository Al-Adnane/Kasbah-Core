// models/silentSpeech.ts — BiometricGuard (restored 2026-09)
//
// This module was missing from the repo and broke the TypeScript build
// (`tsc -p tsconfig.json` failed with TS2307) and the dist/ entry point.
//
// DESIGN: Kasbah's silent-speech capability is DEFENSIVE ONLY. The guard
// refuses biometric / silent-speech intent inference — it never performs
// surveillance. Submitting frames or audio always returns a BLOCK.

export interface SilentSpeechInput {
  videoFrames?: number[][];
  audioFeatures?: number[];
  timestamp?: number;
}

export interface SilentSpeechResult {
  verdict: 'BLOCK';
  blocked: true;
  reason: string;
  policy: string;
  timestamp: number;
  processed: {
    videoFrames: number;
    audioFeatures: boolean;
  };
}

export class BiometricGuard {
  /**
   * Evaluate a silent-speech / biometric inference request.
   * Always BLOCKs — privacy-first, on-device, no surveillance.
   */
  evaluate(input: SilentSpeechInput): SilentSpeechResult {
    const timestamp = typeof input?.timestamp === 'number' ? input.timestamp : Date.now();
    return {
      verdict: 'BLOCK',
      blocked: true,
      reason:
        'Biometric/silent-speech intent inference is not performed. ' +
        'Kasbah protects against this surveillance — it does not enable it.',
      policy: 'biometric-defensive-block',
      timestamp,
      processed: {
        videoFrames: Array.isArray(input?.videoFrames) ? input.videoFrames.length : 0,
        audioFeatures: Array.isArray(input?.audioFeatures) && input.audioFeatures.length > 0,
      },
    };
  }
}

export default BiometricGuard;
