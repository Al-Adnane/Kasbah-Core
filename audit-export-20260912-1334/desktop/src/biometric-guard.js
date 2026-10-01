'use strict';

/**
 * Local BIOMETRIC_GUARD + silent-speech surveillance scanner.
 * Defensive only: flags text/code that attempts covert biometric intent
 * inference (silent-speech, subvocal, faceprint, BCI, micro-expression).
 * Does NOT perform that analysis.
 */

const PACK = [
  { id: 'B-002', label: 'Silent-speech / subvocal / BCI', re: /silent.?speech|sub-?vocal(?:iz|is)?(?:ation|ed|ing)?|electromyograph|\bEMG\b|throat.?mic|neural.?intent|brain.?computer.?interface|\bBCI\b/i },
  { id: 'B-004', label: 'Facial feature / faceprint', re: /facial.?landmark|\bFACS\b|action.?unit|lip.?read|gaze.?track|pupil.?dilat|iris.?scan|retina.?scan|face.?embedding|faceprint/i },
  { id: 'B-006', label: 'QAI / mind-read vector', re: /apple.?silent.?speech|silent.?speech.?recognition|qai.?intent|quantum.?intent.?infer|covert.?intent.?read|mind.?read/i },
  { id: 'B-001', label: 'Facial capture for intent', re: /micro.?expression|emotion.?infer|gaze.?infer|facial.?intent|affect.?computing/i },
  { id: 'fields', label: 'Surveillance payload fields', re: /\b(?:subvocalization|silent_speech|facial_landmarks|lip_frames|bci_signal|emg_capture|face_embedding|gaze_vector)\b/ },
];

const VERBS = /\b(?:CAPTURE_VIDEO|ACCESS_CAMERA|RECORD_WEBCAM|RECORD_AUDIO|ACCESS_MICROPHONE|INFER|PROFILE|CLASSIFY)\b/;

function scanText(text) {
  const t = String(text || '');
  if (!t) return { found: false, findings: [], pack: 'BIOMETRIC_GUARD' };
  const findings = [];
  for (const p of PACK) {
    if (p.re.test(t)) findings.push({ id: p.id, label: p.label });
  }
  if (VERBS.test(t) && findings.length) {
    findings.push({ id: 'B-007', label: 'Surveillance verb + biometric target' });
  }
  return {
    found: findings.length > 0,
    findings,
    pack: 'BIOMETRIC_GUARD',
    severity: findings.some((f) => f.id !== 'B-007') ? 'BLOCK' : (findings.length ? 'WARN' : 'OK'),
    note: findings.length
      ? 'Covert biometric / silent-speech surveillance vector — blocked by BIOMETRIC_GUARD'
      : 'No biometric-surveillance vectors',
  };
}

module.exports = { scanText, PACK, name: 'BIOMETRIC_GUARD' };
