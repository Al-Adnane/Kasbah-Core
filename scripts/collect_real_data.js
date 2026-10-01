#!/usr/bin/env node
/**
 * Kasbah Real Data Collection Scripts
 * 
 * Collects REAL training data for validation - ALL FREE, NO API KEYS NEEDED:
 * - HC3 (Human-ChatGPT Comparison Corpus) - 10,000+ samples
 * - DFDC (Deepfake Detection Challenge) - 100,000+ videos
 * - Common Voice (Mozilla) - 10,000+ hours
 * - LibriSpeech - 100+ hours
 * - Celeb-DF - 5,639 videos
 * - WildDeepfake - 7,000+ images
 * 
 * Plus access requests for:
 * - FaceForensics++ (FREE, 1-2 week approval)
 * - ASVspoof (FREE, 1 week approval)
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { execSync } = require('child_process');

// Configuration
const DATA_DIR = path.join(__dirname, '..', 'real_training_data');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  console.log('✅ Created data directory:', DATA_DIR);
}

// ============================================================================
// 1. DOWNLOAD HC3 DATASET (Human-ChatGPT Comparison Corpus) - FREE
// ============================================================================

async function downloadHC3() {
  console.log('\n📥 Downloading HC3 dataset (10,000+ ChatGPT samples)...');
  console.log('   Source: https://huggingface.co/datasets/Hello-SimpleAI/HC3');
  
  // Try multiple URLs (HC3 has moved)
  const urls = [
    'https://huggingface.co/datasets/Hello-SimpleAI/HC3/resolve/main/hc3_en.json',
    'https://huggingface.co/datasets/Hello-SimpleAI/HC3/resolve/main/hc3_en_partial.json',
    'https://raw.githubusercontent.com/Hello-SimpleAI/chatgpt-comparison-detection/main/hc3_en.json'
  ];
  
  const outputFile = path.join(DATA_DIR, 'hc3_dataset.json');
  
  return new Promise((resolve, reject) => {
    console.log('   Downloading... (this may take 2-5 minutes)');
    
    // Try each URL until one works
    let currentUrl = 0;
    tryDownload();
    
    function tryDownload() {
      if (currentUrl >= urls.length) {
        // All URLs failed - provide manual instructions
        console.log('\n   ⚠️ Automatic download failed - manual download required');
        console.log('   Manual download:');
        console.log('   1. Visit: https://huggingface.co/datasets/Hello-SimpleAI/HC3');
        console.log('   2. Click "Download" on hc3_en.json');
        console.log('   3. Save to:', outputFile);
        console.log('');
        console.log('   Alternative: Use HuggingFace datasets library:');
        console.log('   pip install datasets');
        console.log('   python3 -c "from datasets import load_dataset; d = load_dataset(\'Hello-SimpleAI/HC3\'); d.save_to_disk(\'hc3_dataset\')"');
        resolve(null);
        return;
      }
      
      const file = fs.createWriteStream(outputFile);
      const url = urls[currentUrl];
      
      https.get(url, (response) => {
        if (response.statusCode !== 200) {
          file.close();
          fs.unlinkSync(outputFile);
          currentUrl++;
          tryDownload();
          return;
        }
        
        const totalSize = parseInt(response.headers['content-length'], 10);
        let downloadedSize = 0;
        
        response.on('data', (chunk) => {
          downloadedSize += chunk.length;
          const percent = ((downloadedSize / totalSize) * 100).toFixed(1);
          process.stdout.write(`\r   Progress: ${percent}%`);
        });
        
        response.pipe(file);
        
        file.on('finish', () => {
          file.close();
          console.log('\n   ✅ HC3 dataset saved to', outputFile);
          
          // Verify and report
          try {
            const data = JSON.parse(fs.readFileSync(outputFile, 'utf8'));
            console.log(`   ✅ Verified: ${Array.isArray(data) ? data.length.toLocaleString() : 'dataset loaded'}`);
          } catch (e) {
            console.log('   ⚠️ Could not verify file contents');
          }
          
          resolve(outputFile);
        });
      }).on('error', () => {
        file.close();
        try { fs.unlinkSync(outputFile); } catch(e) {}
        currentUrl++;
        tryDownload();
      });
    }
  });
}

// ============================================================================
// 2. DOWNLOAD WILDDEEPFAKE DATASET - FREE
// ============================================================================

async function downloadWildDeepfake() {
  console.log('\n📥 Downloading WildDeepfake dataset (7,000+ images)...');
  console.log('   Source: https://github.com/deepfakefakes/wilddeepfake');
  
  const outputDir = path.join(DATA_DIR, 'wilddeepfake');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  // Download the JSON file with metadata
  const metadataUrl = 'https://raw.githubusercontent.com/deepfakefakes/wilddeepfake/main/metadata.json';
  const outputFile = path.join(outputDir, 'metadata.json');
  
  return new Promise((resolve, reject) => {
    console.log('   Downloading metadata...');
    
    const file = fs.createWriteStream(outputFile);
    
    https.get(metadataUrl, (response) => {
      if (response.statusCode !== 200) {
        console.log('   ⚠️ Could not download metadata (dataset may require manual download)');
        console.log('   Manual: git clone https://github.com/deepfakefakes/wilddeepfake.git');
        resolve(null);
        return;
      }
      
      response.pipe(file);
      
      file.on('finish', () => {
        file.close();
        console.log('   ✅ WildDeepfake metadata saved');
        console.log('   📝 To download images: git clone https://github.com/deepfakefakes/wilddeepfake.git');
        resolve(outputFile);
      });
    }).on('error', () => {
      console.log('   ⚠️ Download failed - manual download required');
      resolve(null);
    });
  });
}

// ============================================================================
// 3. DOWNLOAD CELEB-DF DATASET - FREE
// ============================================================================

function downloadCelebDF() {
  console.log('\n📥 Celeb-DF Dataset (5,639 videos)');
  console.log('   Source: http://www.cs.albany.edu/~lsw/celeb-deepfakeforensics.html');
  console.log('');
  console.log('   Celeb-DF requires filling out a request form.');
  console.log('');
  console.log('   Steps:');
  console.log('   1. Visit: http://www.cs.albany.edu/~lsw/celeb-deepfakeforensics.html');
  console.log('   2. Fill out the data request form');
  console.log('   3. Wait for approval (typically 1-3 days)');
  console.log('   4. Download link will be provided');
  console.log('');
  
  // Save request instructions
  const instructions = `
Celeb-DF Dataset Request
========================

URL: http://www.cs.albany.edu/~lsw/celeb-deepfakeforensics.html

Dataset Info:
- 5,639 videos
- 590 real videos from YouTube
- 5,049 synthetic videos generated from real videos
- High quality deepfakes

Request Process:
1. Fill out the data request form on the website
2. Provide institutional email (preferred)
3. State research purpose: "Training deepfake detection models for Kasbah Guard security platform"
4. Wait 1-3 days for approval
5. Download link will be emailed

Expected Download Size: ~50GB
`.trim();
  
  const outputFile = path.join(DATA_DIR, 'celebdf_request_instructions.txt');
  fs.writeFileSync(outputFile, instructions);
  console.log('   ✅ Instructions saved to:', outputFile);
}

// ============================================================================
// 4. DOWNLOAD DFDC (Deepfake Detection Challenge) - FREE
// ============================================================================

function downloadDFDC() {
  console.log('\n📥 DFDC Dataset (100,000+ videos)');
  console.log('   Source: https://dfdc.dataset.org/');
  console.log('   Hosted on: AWS Open Data');
  console.log('');
  console.log('   DFDC is available via AWS Open Data Registry.');
  console.log('');
  console.log('   Access Options:');
  console.log('   1. AWS S3 (if you have AWS account):');
  console.log('      s3://dfdc/');
  console.log('');
  console.log('   2. Direct download (smaller subsets):');
  console.log('      https://www.kaggle.com/c/deepfake-detection-challenge/data');
  console.log('');
  console.log('   3. Kaggle (requires Kaggle account):');
  console.log('      kaggle competitions download -c deepfake-detection-challenge');
  console.log('');
  
  // Save download script
  const script = `#!/bin/bash
# DFDC Download Script

# Option 1: AWS S3 (requires AWS CLI configured)
# aws s3 cp s3://dfdc/ ./dfdc/ --recursive

# Option 2: Kaggle (requires kaggle CLI configured)
kaggle competitions download -c deepfake-detection-challenge
unzip deepfake-detection-challenge.zip -d dfdc/

# Expected size: ~100GB for full dataset
echo "✅ DFDC download complete"
`.trim();
  
  const outputFile = path.join(DATA_DIR, 'dfdc_download.sh');
  fs.writeFileSync(outputFile, script);
  fs.chmodSync(outputFile, '755');
  console.log('   ✅ Download script saved to:', outputFile);
}

// ============================================================================
// 5. DOWNLOAD COMMON VOICE (Mozilla) - FREE
// ============================================================================

function downloadCommonVoice() {
  console.log('\n📥 Common Voice Dataset (10,000+ hours, 60+ languages)');
  console.log('   Source: https://commonvoice.mozilla.org/');
  console.log('');
  console.log('   Common Voice is FREE and open source.');
  console.log('');
  console.log('   Download Options:');
  console.log('   1. Direct from Mozilla (latest version):');
  console.log('      https://commonvoice.mozilla.org/en/datasets');
  console.log('');
  console.log('   2. Specific languages (example for English):');
  console.log('      wget https://mozilla-common-voice-datasets.s3.amazonaws.com/cv-corpus-15.0/en.tar.gz');
  console.log('');
  console.log('   3. Using HuggingFace datasets (easiest):');
  console.log('      pip install datasets');
  console.log('      from datasets import load_dataset');
  console.log('      dataset = load_dataset("mozilla-foundation/common_voice_11_0", "en")');
  console.log('');
  
  // Save download script
  const script = `#!/bin/bash
# Common Voice Download Script

# Option 1: Direct download (English, ~40GB)
wget https://mozilla-common-voice-datasets.s3.amazonaws.com/cv-corpus-15.0/en.tar.gz
tar -xzf en.tar.gz -d common_voice/

# Option 2: Using HuggingFace (Python)
# pip install datasets
# python3 -c "
# from datasets import load_dataset
# dataset = load_dataset('mozilla-foundation/common_voice_11_0', 'en')
# dataset.save_to_disk('common_voice_dataset')
# "

echo "✅ Common Voice download complete"
`.trim();
  
  const outputFile = path.join(DATA_DIR, 'common_voice_download.sh');
  fs.writeFileSync(outputFile, script);
  fs.chmodSync(outputFile, '755');
  console.log('   ✅ Download script saved to:', outputFile);
}

// ============================================================================
// 2. DOWNLOAD HC3 DATASET (Human-ChatGPT Comparison Corpus)
// ============================================================================

async function downloadHC3() {
  console.log('\n📥 Downloading HC3 dataset...');
  
  const hc3Url = 'https://huggingface.co/datasets/Hello-SimpleAI/HC3/resolve/main/hc3_en.json';
  const outputFile = path.join(DATA_DIR, 'hc3_dataset.json');
  
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(outputFile);
    
    https.get(hc3Url, (response) => {
      if (response.statusCode !== 200) {
        reject(new Error(`Failed to download HC3: ${response.statusCode}`));
        return;
      }
      
      response.pipe(file);
      
      file.on('finish', () => {
        file.close();
        console.log(`✅ HC3 dataset saved to ${outputFile}`);
        resolve(outputFile);
      });
    }).on('error', reject);
  });
}

// ============================================================================
// 3. REQUEST FACEFORENSICS++ ACCESS
// ============================================================================

function requestFaceForensicsAccess() {
  console.log('\n📧 FaceForensics++ Access Request');
  console.log('================================');
  console.log('');
  console.log('FaceForensics++ requires academic/research access.');
  console.log('');
  console.log('Steps to request access:');
  console.log('1. Visit: https://github.com/ondyix/FaceForensics');
  console.log('2. Fill out the access request form');
  console.log('3. Provide institutional email (.edu preferred)');
  console.log('4. Wait 1-2 weeks for approval');
  console.log('');
  console.log('Alternative public datasets:');
  console.log('- Celeb-DF: http://www.cs.albany.edu/~lsw/celeb-deepfakeforensics.html');
  console.log('- DFDC (Deepfake Detection Challenge): https://dfdc.dataset.org/');
  console.log('- DeepFakeTIMIT: https://github.com/guillermomalvido/DeepFakeTIMIT');
  console.log('');
  
  // Save request template
  const template = `
Subject: FaceForensics++ Access Request

Dear FaceForensics++ Team,

I am requesting access to the FaceForensics++ dataset for research purposes.

Research Purpose: Training and validating AI deepfake detection models for Kasbah Guard, a security platform that detects AI-generated content, deepfakes, and voice clones.

Institution: [Your Institution]
Research Group: [Your Research Group]
Intended Use: Academic/Research (non-commercial)
Expected Dataset Size: ~1000 videos for initial validation

We agree to:
- Use the dataset only for research purposes
- Not redistribute the dataset
- Cite the FaceForensics++ paper in any publications
- Comply with all dataset terms and conditions

Thank you for considering our request.

Best regards,
[Your Name]
[Your Title]
[Your Institution]
[Your Email]
`.trim();
  
  const outputFile = path.join(DATA_DIR, 'faceforensics_request_template.txt');
  fs.writeFileSync(outputFile, template);
  console.log(`✅ Request template saved to ${outputFile}`);
}

// ============================================================================
// 4. REQUEST ASVSPOOF ACCESS
// ============================================================================

function requestASVspoofAccess() {
  console.log('\n📧 ASVspoof Access Request');
  console.log('=========================');
  console.log('');
  console.log('ASVspoof requires registration for access.');
  console.log('');
  console.log('Steps to request access:');
  console.log('1. Visit: https://www.asvspoof.org/');
  console.log('2. Register for ASVspoof 2021 dataset');
  console.log('3. Provide institutional affiliation');
  console.log('4. Wait ~1 week for approval');
  console.log('');
  console.log('Alternative public datasets:');
  console.log('- LibriSpeech: http://www.openslr.org/12/ (open access)');
  console.log('- Common Voice: https://commonvoice.mozilla.org/ (open access)');
  console.log('- VCTK: https://datashare.ed.ac.uk/handle/10283/3443 (open access)');
  console.log('');
  
  // Save request template
  const template = `
Subject: ASVspoof 2021 Dataset Access Request

Dear ASVspoof Team,

I am requesting access to the ASVspoof 2021 dataset for research purposes.

Research Purpose: Training and validating voice cloning detection models for Kasbah Guard, a security platform that detects synthetic voice and audio deepfakes.

Institution: [Your Institution]
Research Group: [Your Research Group]
Intended Use: Academic/Research (non-commercial)
Expected Dataset Size: Full dataset for comprehensive validation

We agree to:
- Use the dataset only for research purposes
- Not redistribute the dataset
- Cite the ASVspoof papers in any publications
- Comply with all dataset terms and conditions

Thank you for considering our request.

Best regards,
[Your Name]
[Your Title]
[Your Institution]
[Your Email]
`.trim();
  
  const outputFile = path.join(DATA_DIR, 'asvspoof_request_template.txt');
  fs.writeFileSync(outputFile, template);
  console.log(`✅ Request template saved to ${outputFile}`);
}

// ============================================================================
// 5. DOWNLOAD LIBRISPEECH (OPEN ACCESS)
// ============================================================================

async function downloadLibriSpeech() {
  console.log('\n📥 Downloading LibriSpeech (open access)...');
  
  const libriSpeechUrl = 'http://www.openslr.org/resources/12/test-clean.tar.gz';
  const outputDir = path.join(DATA_DIR, 'librispeech');
  
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  console.log('⚠️ LibriSpeech is 580MB - download may take several minutes');
  console.log('');
  console.log('Download URL:', libriSpeechUrl);
  console.log('Output directory:', outputDir);
  console.log('');
  console.log('Manual download instructions:');
  console.log('1. Visit: http://www.openslr.org/12/');
  console.log('2. Download test-clean.tar.gz');
  console.log('3. Extract to:', outputDir);
  console.log('');
  
  // Save download script
  const script = `#!/bin/bash
# LibriSpeech download script
cd ${outputDir}
wget http://www.openslr.org/resources/12/test-clean.tar.gz
tar -xzf test-clean.tar.gz
rm test-clean.tar.gz
echo "✅ LibriSpeech downloaded and extracted"
`.trim();
  
  const scriptFile = path.join(outputDir, 'download.sh');
  fs.writeFileSync(scriptFile, script);
  fs.chmodSync(scriptFile, '755');
  console.log(`✅ Download script saved to ${scriptFile}`);
}

// ============================================================================
// MAIN EXECUTION - ALL FREE DATASETS, NO API KEYS NEEDED
// ============================================================================

async function main() {
  console.log('='.repeat(60));
  console.log('KASBAH REAL DATA COLLECTION');
  console.log('ALL FREE - NO API KEYS REQUIRED');
  console.log('='.repeat(60));

  // 1. Download FREE open datasets
  console.log('\n📥 DOWNLOADING FREE DATASETS...\n');
  
  try {
    // HC3 - 10,000+ ChatGPT samples (IMMEDIATE)
    await downloadHC3();
    
    // WildDeepfake - 7,000+ images (IMMEDIATE)
    await downloadWildDeepfake();
    
  } catch (error) {
    console.error('❌ Error downloading datasets:', error.message);
  }

  // 2. Provide instructions for FREE datasets (manual download)
  console.log('\n');
  downloadCelebDF();      // 5,639 videos (request form)
  downloadDFDC();         // 100,000+ videos (AWS/Kaggle)
  downloadCommonVoice();  // 10,000+ hours (direct download)
  downloadLibriSpeech();  // 100+ hours (direct download)

  // 3. Request access to restricted (but FREE) datasets
  console.log('\n');
  requestFaceForensicsAccess();  // FREE, 1-2 week approval
  requestASVspoofAccess();       // FREE, 1 week approval

  console.log('\n' + '='.repeat(60));
  console.log('DATA COLLECTION SETUP COMPLETE');
  console.log('='.repeat(60));
  console.log('');
  console.log('📊 SUMMARY OF FREE DATASETS:');
  console.log('');
  console.log('✅ IMMEDIATE (Download Now):');
  console.log('   • HC3: 10,000+ ChatGPT samples');
  console.log('   • WildDeepfake: 7,000+ deepfake images');
  console.log('   • LibriSpeech: 100+ hours natural speech');
  console.log('   • Common Voice: 10,000+ hours (Mozilla)');
  console.log('');
  console.log('⏳ REQUEST ACCESS (FREE, 1-2 weeks):');
  console.log('   • FaceForensics++: 1,000+ deepfake videos');
  console.log('   • ASVspoof 2021: Voice cloning samples');
  console.log('   • Celeb-DF: 5,639 high-quality deepfakes');
  console.log('');
  console.log('💾 LARGE DATASETS (Download Scripts Provided):');
  console.log('   • DFDC: 100,000+ videos (AWS/Kaggle)');
  console.log('');
  console.log('📁 Data directory:', DATA_DIR);
  console.log('');
  console.log('🚀 NEXT STEPS:');
  console.log('   1. Review downloaded files in:', DATA_DIR);
  console.log('   2. Run download scripts for large datasets:');
  console.log('      cd', DATA_DIR);
  console.log('      bash common_voice_download.sh');
  console.log('      bash dfdc_download.sh');
  console.log('   3. Submit access requests (templates provided)');
  console.log('');
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}

module.exports = {
  downloadHC3,
  downloadWildDeepfake,
  downloadCelebDF,
  downloadDFDC,
  downloadCommonVoice,
  downloadLibriSpeech,
  requestFaceForensicsAccess,
  requestASVspoofAccess
};
