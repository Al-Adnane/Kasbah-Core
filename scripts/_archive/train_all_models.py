#!/usr/bin/env python3
"""
Kasbah ML Model Training Pipeline
==================================
Trains all ML models and exports to ONNX format.

Usage:
    python train_all_models.py --all
    python train_all_models.py --image-forgery
    python train_all_models.py --audio-anomaly
    python train_all_models.py --secret-classifier
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
from datetime import datetime


def print_header(text):
    """Print formatted header."""
    print("\n" + "=" * 70)
    print(f" {text}")
    print("=" * 70 + "\n")


def check_dependencies():
    """Check required dependencies."""
    print_header("CHECKING DEPENDENCIES")
    
    missing = []
    
    try:
        import torch
        print(f"✅ PyTorch {torch.__version__}")
    except ImportError:
        missing.append("torch")
        print("❌ PyTorch - NOT INSTALLED")
    
    try:
        import onnx
        print(f"✅ ONNX {onnx.__version__}")
    except ImportError:
        missing.append("onnx")
        print("❌ ONNX - NOT INSTALLED")
    
    try:
        import onnxruntime
        print(f"✅ ONNX Runtime {onnxruntime.__version__}")
    except ImportError:
        missing.append("onnxruntime")
        print("❌ ONNX Runtime - NOT INSTALLED")
    
    try:
        import numpy
        print(f"✅ NumPy {numpy.__version__}")
    except ImportError:
        missing.append("numpy")
        print("❌ NumPy - NOT INSTALLED")
    
    try:
        import librosa
        print(f"✅ librosa - installed")
    except ImportError:
        print("⚠️  librosa - NOT INSTALLED (audio training will be limited)")
    
    try:
        from PIL import Image
        print(f"✅ Pillow - installed")
    except ImportError:
        missing.append("pillow")
        print("❌ Pillow - NOT INSTALLED")
    
    try:
        import sklearn
        print(f"✅ scikit-learn {sklearn.__version__}")
    except ImportError:
        missing.append("scikit-learn")
        print("❌ scikit-learn - NOT INSTALLED")
    
    if missing:
        print(f"\n❌ MISSING DEPENDENCIES: {', '.join(missing)}")
        print(f"\nInstall with:")
        print(f"  pip install {' '.join(missing)}")
        print(f"\nOr install all:")
        print(f"  pip install torch onnx onnxruntime numpy pillow scikit-learn librosa scipy")
        return False
    
    print("\n✅ All dependencies satisfied")
    return True


def train_image_forgery_cnn(epochs=50, batch_size=32, device='cpu'):
    """Train image forgery CNN model."""
    print_header("TRAINING IMAGE FORGERY CNN")
    
    script = Path(__file__).parent / "Kasbah-Core" / "core" / "ml" / "train_image_forgery_cnn.py"
    
    if not script.exists():
        print(f"❌ Training script not found: {script}")
        return False
    
    cmd = [
        sys.executable, str(script),
        "--train",
        "--export-onnx",
        "--epochs", str(epochs),
        "--batch-size", str(batch_size),
        "--device", device,
    ]
    
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=script.parent)
    
    if result.returncode == 0:
        print("\n✅ Image forgery CNN training complete")
        
        # Verify model was created
        model_path = script.parent / "models" / "image_forgery_cnn.onnx"
        if model_path.exists():
            print(f"✅ Model saved: {model_path}")
            print(f"   Size: {model_path.stat().st_size / 1024 / 1024:.2f} MB")
            return True
        else:
            print(f"❌ Model file not found: {model_path}")
            return False
    else:
        print(f"\n❌ Training failed with exit code {result.returncode}")
        return False


def train_audio_autoencoder(epochs=50, batch_size=32, device='cpu'):
    """Train audio autoencoder model."""
    print_header("TRAINING AUDIO AUTOENCODER")
    
    script = Path(__file__).parent / "Kasbah-Core" / "core" / "ml" / "train_audio_autoencoder.py"
    
    if not script.exists():
        print(f"❌ Training script not found: {script}")
        return False
    
    cmd = [
        sys.executable, str(script),
        "--train",
        "--export-onnx",
        "--epochs", str(epochs),
        "--batch-size", str(batch_size),
        "--device", device,
    ]
    
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=script.parent)
    
    if result.returncode == 0:
        print("\n✅ Audio autoencoder training complete")
        
        # Verify model was created
        model_path = script.parent / "models" / "audio_autoencoder.onnx"
        if model_path.exists():
            print(f"✅ Model saved: {model_path}")
            print(f"   Size: {model_path.stat().st_size / 1024 / 1024:.2f} MB")
            
            # Check threshold file
            threshold_path = script.parent / "models" / "audio_autoencoder.threshold.json"
            if threshold_path.exists():
                print(f"✅ Threshold saved: {threshold_path}")
            else:
                print(f"⚠️  Threshold file not created")
            
            return True
        else:
            print(f"❌ Model file not found: {model_path}")
            return False
    else:
        print(f"\n❌ Training failed with exit code {result.returncode}")
        return False


def train_secret_classifier():
    """Train secret document classifier."""
    print_header("TRAINING SECRET CLASSIFIER")
    
    script = Path(__file__).parent / "Kasbah-Core" / "core" / "ml" / "kasbah_ml_classifier.py"
    
    if not script.exists():
        print(f"❌ Training script not found: {script}")
        return False
    
    # Check if training data exists
    data_path = script.parent / "training_data.json"
    if not data_path.exists():
        print(f"⚠️  Training data not found: {data_path}")
        print("   Creating synthetic training data...")
    
    cmd = [
        sys.executable, str(script),
        "--train",
    ]
    
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=script.parent)
    
    if result.returncode == 0:
        print("\n✅ Secret classifier training complete")
        return True
    else:
        print(f"\n❌ Training failed with exit code {result.returncode}")
        return False


def verify_models():
    """Verify all trained models."""
    print_header("VERIFYING MODELS")
    
    models_dir = Path(__file__).parent / "Kasbah-Core" / "core" / "ml" / "models"
    
    if not models_dir.exists():
        print("❌ Models directory not found")
        return False
    
    models = {
        "image_forgery_cnn.onnx": "Image Forgery CNN",
        "audio_autoencoder.onnx": "Audio Autoencoder",
        "audio_autoencoder.threshold.json": "Audio Threshold",
    }
    
    all_present = True
    
    for model_file, description in models.items():
        model_path = models_dir / model_file
        if model_path.exists():
            size_mb = model_path.stat().st_size / 1024 / 1024
            print(f"✅ {description}: {model_file} ({size_mb:.2f} MB)")
        else:
            print(f"❌ {description}: {model_file} - MISSING")
            all_present = False
    
    # Verify ONNX models
    print("\nVerifying ONNX models...")
    
    try:
        import onnx
        
        for model_file in ["image_forgery_cnn.onnx", "audio_autoencoder.onnx"]:
            model_path = models_dir / model_file
            if model_path.exists():
                try:
                    model = onnx.load(str(model_path))
                    onnx.checker.check_model(model)
                    print(f"✅ {model_file} - Valid ONNX")
                except Exception as e:
                    print(f"❌ {model_file} - Invalid: {e}")
                    all_present = False
    except ImportError:
        print("⚠️  ONNX not installed, skipping validation")
    
    return all_present


def run_tests():
    """Run ML component tests."""
    print_header("RUNNING ML TESTS")
    
    test_script = Path(__file__).parent / "Kasbah-site" / "kasbah-guard-dist" / "core" / "ml" / "run_all_tests.py"
    
    if not test_script.exists():
        print(f"❌ Test script not found: {test_script}")
        return False
    
    cmd = [
        sys.executable, str(test_script),
        "--complete",
    ]
    
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=test_script.parent)
    
    if result.returncode == 0:
        print("\n✅ All ML tests passed")
        return True
    else:
        print(f"\n⚠️  Some tests failed (exit code {result.returncode})")
        return False


def main():
    parser = argparse.ArgumentParser(description='Kasbah ML Model Training Pipeline')
    
    parser.add_argument('--all', action='store_true',
                       help='Train all models')
    parser.add_argument('--image-forgery', action='store_true',
                       help='Train image forgery CNN only')
    parser.add_argument('--audio-anomaly', action='store_true',
                       help='Train audio autoencoder only')
    parser.add_argument('--secret-classifier', action='store_true',
                       help='Train secret classifier only')
    parser.add_argument('--verify', action='store_true',
                       help='Verify trained models only')
    parser.add_argument('--test', action='store_true',
                       help='Run tests after training')
    parser.add_argument('--epochs', type=int, default=50,
                       help='Number of training epochs (default: 50)')
    parser.add_argument('--batch-size', type=int, default=32,
                       help='Batch size (default: 32)')
    parser.add_argument('--device', type=str, default='cpu',
                       help='Device (cpu or cuda)')
    
    args = parser.parse_args()
    
    print_header("KASBAH ML MODEL TRAINING PIPELINE")
    print(f"Date: {datetime.now().isoformat()}")
    print(f"Python: {sys.version}")
    print(f"Working Directory: {Path.cwd()}")
    
    # Check dependencies first
    if not check_dependencies():
        print("\n❌ Please install missing dependencies and re-run")
        sys.exit(1)
    
    # Determine what to train
    train_image = args.all or args.image_forgery
    train_audio = args.all or args.audio_anomaly
    train_secret = args.all or args.secret_classifier
    verify_only = args.verify
    run_test = args.test
    
    # If no specific training requested, show help
    if not any([train_image, train_audio, train_secret, verify_only]):
        parser.print_help()
        print("\n\nQuick Start:")
        print("  python train_all_models.py --all  # Train all models")
        sys.exit(0)
    
    results = {}
    
    # Train models
    if train_image:
        results['image'] = train_image_forgery_cnn(
            epochs=args.epochs,
            batch_size=args.batch_size,
            device=args.device
        )
    
    if train_audio:
        results['audio'] = train_audio_autoencoder(
            epochs=args.epochs,
            batch_size=args.batch_size,
            device=args.device
        )
    
    if train_secret:
        results['secret'] = train_secret_classifier()
    
    # Verify models
    if verify_only or results:
        results['verify'] = verify_models()
    
    # Run tests
    if run_test:
        results['test'] = run_tests()
    
    # Summary
    print_header("TRAINING SUMMARY")
    
    for task, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {status} {task}")
    
    all_success = all(results.values())
    
    if all_success:
        print("\n🎉 ALL TRAINING COMPLETE!")
        print("\nNext steps:")
        print("  1. Copy models to deployment location")
        print("  2. Run integration tests")
        print("  3. Deploy to staging environment")
    else:
        print("\n⚠️  SOME TRAINING FAILED")
        print("  Check error messages above and re-run failed components")
    
    sys.exit(0 if all_success else 1)


if __name__ == '__main__':
    main()
