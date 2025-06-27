#!/usr/bin/env python3
"""
Generate test WAV file with recognizable patterns for latency testing.
Creates alternating patterns of silence and tones.
"""

import wave
import struct
import math

def generate_test_wav(filename="test_audio.wav", sample_rate=11025, duration_sec=3):
    """
    Generate a WAV file with distinct patterns:
    - 500ms silence
    - 500ms 440Hz tone (A note)
    - 500ms silence  
    - 500ms 880Hz tone (A note one octave higher)
    - 500ms silence
    - 500ms white noise
    - Repeat
    """
    
    channels = 1  # Mono
    sample_width = 2  # 16-bit
    
    # Calculate samples
    samples_per_pattern = int(sample_rate * 0.5)  # 500ms each pattern
    total_samples = sample_rate * duration_sec
    
    audio_data = []
    
    pattern_cycle = 0
    while len(audio_data) < total_samples:
        pattern_type = pattern_cycle % 6
        
        if pattern_type in [0, 2, 4]:  # Silence
            # Generate silence (all zeros)
            for _ in range(samples_per_pattern):
                audio_data.append(0)
                
        elif pattern_type == 1:  # 440Hz tone
            # Generate 440Hz sine wave
            for i in range(samples_per_pattern):
                t = i / sample_rate
                value = int(16000 * math.sin(2 * math.pi * 440 * t))
                audio_data.append(value)
                
        elif pattern_type == 3:  # 880Hz tone
            # Generate 880Hz sine wave
            for i in range(samples_per_pattern):
                t = i / sample_rate
                value = int(16000 * math.sin(2 * math.pi * 880 * t))
                audio_data.append(value)
                
        elif pattern_type == 5:  # White noise
            # Generate white noise
            import random
            for _ in range(samples_per_pattern):
                value = random.randint(-8000, 8000)
                audio_data.append(value)
        
        pattern_cycle += 1
    
    # Trim to exact duration
    audio_data = audio_data[:total_samples]
    
    # Write WAV file
    with wave.open(filename, 'wb') as wav_file:
        wav_file.setnchannels(channels)
        wav_file.setsampwidth(sample_width)
        wav_file.setframerate(sample_rate)
        
        # Pack audio data as 16-bit signed integers
        packed_data = b''.join(struct.pack('<h', sample) for sample in audio_data)
        wav_file.writeframes(packed_data)
    
    print(f"Generated {filename} with patterns:")
    print("- 500ms silence")
    print("- 500ms 440Hz tone")
    print("- 500ms silence")
    print("- 500ms 880Hz tone")
    print("- 500ms silence")
    print("- 500ms white noise")
    print(f"- Total duration: {duration_sec} seconds")
    
    return audio_data

def create_pattern_dictionary():
    """
    Create a dictionary of common audio patterns to search for.
    Returns patterns as both hex strings and byte descriptions.
    """
    
    patterns = {
        "silence_16bit": {
            "description": "16-bit silence (consecutive zeros)",
            "hex": "00000000000000000000",  # 10 bytes of silence
            "hex_variations": [
                "00000000000000000000",  # Perfect silence
                "0000010000ff00000100",  # Near silence (±1 values)
            ],
            "bytes": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        },
        
        "440hz_peak": {
            "description": "Positive peak of 440Hz sine wave at 16000 amplitude",
            "hex": "803e",  # 16000 in little-endian hex
            "hex_variations": [
                "803e",  # Exact peak
                "7f3e", "813e",  # Near peak
            ],
            "bytes": b"\x80\x3e"
        },
        
        "880hz_peak": {
            "description": "Positive peak of 880Hz sine wave",
            "hex": "803e",  # Same amplitude, different frequency
            "bytes": b"\x80\x3e"
        },
        
        "silence_to_tone_transition": {
            "description": "Transition from silence to tone",
            "hex": "000000000000[0-9a-f]{2}[0-9a-f]{2}",  # Regex pattern
            "note": "Look for zeros followed by non-zero values"
        },
        
        "tone_to_silence_transition": {
            "description": "Transition from tone to silence",
            "hex": "[0-9a-f]{2}[0-9a-f]{2}00000000",  # Regex pattern
            "note": "Look for non-zero values followed by zeros"
        }
    }
    
    return patterns

if __name__ == "__main__":
    # Generate test audio file
    audio_data = generate_test_wav("test_audio.wav")
    
    # Print pattern dictionary
    print("\n" + "="*60)
    print("Audio Pattern Dictionary for eBPF Detection:")
    print("="*60)
    
    patterns = create_pattern_dictionary()
    for name, pattern in patterns.items():
        print(f"\n{name}:")
        print(f"  Description: {pattern['description']}")
        print(f"  Hex pattern: {pattern.get('hex', 'N/A')}")
        if 'hex_variations' in pattern:
            print(f"  Variations: {', '.join(pattern['hex_variations'])}")
        if 'note' in pattern:
            print(f"  Note: {pattern['note']}")
    
    # Show first 100 samples as hex for debugging
    print("\n" + "="*60)
    print("First 100 bytes of generated audio (as hex):")
    print("="*60)
    
    hex_samples = []
    for i in range(min(50, len(audio_data))):
        # Convert to 16-bit signed, then to bytes
        sample_bytes = struct.pack('<h', audio_data[i])
        hex_samples.append(sample_bytes.hex())
    
    print(" ".join(hex_samples))