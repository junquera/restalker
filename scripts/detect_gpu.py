#!/usr/bin/env python3
"""
GPU Detection Script for reStalker

Detects available GPU hardware and recommends the appropriate installation method.

Usage:
    python scripts/detect_gpu.py              # Show detailed information
    python scripts/detect_gpu.py --output     # Output extra name for scripting
    python scripts/detect_gpu.py --pip        # Show pip install command
    python scripts/detect_gpu.py --poetry     # Show poetry install command
    python scripts/detect_gpu.py --req        # Show requirements file to use
"""

import subprocess
import sys
import platform


def detect_nvidia():
    """Check for NVIDIA GPU with CUDA support."""
    try:
        result = subprocess.run(
            ['nvidia-smi'],
            capture_output=True,
            check=True,
            timeout=5
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def detect_amd():
    """Check for AMD GPU."""
    try:
        # Check lspci for AMD VGA
        result = subprocess.run(
            ['lspci'],
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout.upper()
        is_amd = 'AMD' in output or 'ATI' in output
        is_vga = 'VGA' in output or 'DISPLAY' in output
        
        return is_amd and is_vga
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # lspci not available (Windows/macOS)
        return False


def check_rocm_installed():
    """Check if ROCm is installed (for AMD GPUs)."""
    try:
        result = subprocess.run(
            ['rocm-smi'],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_gpu_info():
    """Get detailed GPU information."""
    info = {
        'has_nvidia': False,
        'has_amd': False,
        'has_rocm': False,
        'platform': platform.system(),
        'recommendation': 'cpu'
    }
    
    info['has_nvidia'] = detect_nvidia()
    info['has_amd'] = detect_amd()
    info['has_rocm'] = check_rocm_installed()
    
    # Determine recommendation
    if info['has_nvidia']:
        info['recommendation'] = 'gpu'
    elif info['has_amd'] and info['has_rocm'] and info['platform'] == 'Linux':
        info['recommendation'] = 'amd-gpu'
    else:
        info['recommendation'] = 'cpu'
    
    return info


def print_detailed_info(info):
    """Print detailed GPU detection information."""
    print("=" * 70)
    print("🔍 reStalker GPU Detection Results")
    print("=" * 70)
    print()
    
    # System information
    print(f"📊 System Information:")
    print(f"   Platform: {info['platform']}")
    print()
    
    # GPU Detection
    print("🎮 GPU Detection:")
    
    if info['has_nvidia']:
        print("   ✅ NVIDIA GPU detected")
        print("      - CUDA support available")
        print("      - Recommended: NVIDIA CUDA installation")
    else:
        print("   ❌ No NVIDIA GPU detected")
    
    print()
    
    if info['has_amd']:
        print("   ✅ AMD GPU detected")
        if info['has_rocm']:
            print("      - ROCm installed")
            if info['platform'] == 'Linux':
                print("      - Recommended: AMD ROCm installation")
            else:
                print("      ⚠️  ROCm only supports Linux")
                print("      - Falling back to CPU-only")
        else:
            print("      ⚠️  ROCm not installed")
            print("      - Install ROCm for GPU acceleration: https://rocm.docs.amd.com/")
            print("      - Falling back to CPU-only")
    else:
        print("   ❌ No AMD GPU detected")
    
    print()
    print("=" * 70)
    print("📦 Recommended Installation:")
    print("=" * 70)
    print()
    
    rec = info['recommendation']
    
    if rec == 'gpu':
        print("🚀 NVIDIA CUDA Installation (Recommended)")
        print()
        print("   Poetry:")
        print("      poetry install --extras gpu")
        print()
        print("   Pip (using setup.py):")
        print("      pip install -e .[gpu]")
        print()
        print("   Pip (using requirements file):")
        print("      pip install -r requirements-gpu-cuda.txt")
        print()
        print("   📊 Expected: ~3.2GB disk space, 5-10x faster performance")
        
    elif rec == 'amd-gpu':
        print("🚀 AMD ROCm Installation (Recommended)")
        print()
        print("   Poetry:")
        print("      poetry install --extras amd-gpu")
        print()
        print("   Pip (using setup.py):")
        print("      pip install -e .[amd-gpu]")
        print()
        print("   Pip (using requirements file):")
        print("      pip install -r requirements-gpu-rocm.txt")
        print()
        print("   📊 Expected: ~3.5GB disk space, 3-7x faster performance")
        
    else:
        if info['has_amd'] or info['has_nvidia']:
            print("ℹ️  CPU-only Installation (GPU available but not configured)")
        else:
            print("ℹ️  CPU-only Installation (No GPU detected)")
        print()
        print("   Poetry:")
        print("      poetry install")
        print()
        print("   Pip (using setup.py):")
        print("      pip install -e .")
        print()
        print("   Pip (using requirements file):")
        print("      pip install -r requirements.txt")
        print()
        print("   📊 Expected: ~500MB disk space, good performance for most use cases")
    
    print()
    print("=" * 70)


def main():
    """Main entry point."""
    info = get_gpu_info()
    
    if '--output' in sys.argv:
        # For scripting: just print the extra name
        if info['recommendation'] == 'cpu':
            print('')  # Empty for default (no extra)
        else:
            print(info['recommendation'])
    
    elif '--pip' in sys.argv:
        # Output pip install command
        if info['recommendation'] == 'cpu':
            print('pip install -e .')
        else:
            print(f'pip install -e .[{info["recommendation"]}]')
    
    elif '--poetry' in sys.argv:
        # Output poetry install command
        if info['recommendation'] == 'cpu':
            print('poetry install')
        else:
            print(f'poetry install --extras {info["recommendation"]}')
    
    elif '--req' in sys.argv:
        # Output requirements file name
        if info['recommendation'] == 'gpu':
            print('requirements-gpu-cuda.txt')
        elif info['recommendation'] == 'amd-gpu':
            print('requirements-gpu-rocm.txt')
        else:
            print('requirements.txt')
    
    else:
        # Default: print detailed information
        print_detailed_info(info)


if __name__ == '__main__':
    main()
