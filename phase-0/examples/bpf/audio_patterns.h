// audio_patterns.h - Audio signature patterns for eBPF detection
#ifndef AUDIO_PATTERNS_H
#define AUDIO_PATTERNS_H

// Pattern types
#define PATTERN_SILENCE         1
#define PATTERN_TONE_440HZ      2
#define PATTERN_TONE_880HZ      3
#define PATTERN_NOISE           4
#define PATTERN_SILENCE_TO_TONE 5
#define PATTERN_TONE_TO_SILENCE 6

// Pattern detection result
struct audio_pattern {
    __u8 pattern_type;
    __u32 offset;        // Offset in packet where pattern found
    __u64 timestamp_ns;  // When pattern was detected
};

// Check if bytes represent silence (all zeros or near-zeros)
static __always_inline int is_silence_pattern(const char *data, int len) {
    if (len < 8) return 0;
    
    // Check for 8 consecutive zero bytes (4 samples in 16-bit audio)
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        // Allow for slight noise (±1)
        if (data[i] != 0x00 && data[i] != 0x01 && data[i] != 0xff)
            return 0;
    }
    return 1;
}

// Check for hex-encoded silence in JSON: "00000000..."
static __always_inline int is_hex_silence_pattern(const char *data, int len) {
    if (len < 16) return 0;  // Need at least 16 hex chars (8 bytes)
    
    // Check for "00000000" pattern
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (data[i] != '0')
            return 0;
    }
    return 1;
}

// Check for silence-to-tone transition
static __always_inline int is_silence_to_tone_transition(const char *data, int len) {
    if (len < 16) return 0;
    
    // First 8 chars should be silence (hex "00000000")
    int has_silence = 1;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (data[i] != '0') {
            has_silence = 0;
            break;
        }
    }
    
    if (!has_silence) return 0;
    
    // Next chars should NOT be silence
    int has_sound = 0;
    #pragma unroll
    for (int i = 8; i < 12; i++) {
        if (data[i] != '0') {
            has_sound = 1;
            break;
        }
    }
    
    return has_sound;
}

// Main pattern search function
static __always_inline int find_audio_pattern(const char *data, int data_len, 
                                             struct audio_pattern *result) {
    // Search for hex-encoded patterns (JSON format)
    // Look for continuous patterns of at least 16 hex characters
    
    #pragma unroll
    for (int i = 0; i < 64; i++) {  // Search first 64 positions
        if (i + 16 > data_len) break;
        
        // Check if this looks like hex data
        int is_hex = 1;
        #pragma unroll
        for (int j = 0; j < 16; j++) {
            char c = data[i + j];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                is_hex = 0;
                break;
            }
        }
        
        if (!is_hex) continue;
        
        // Check for silence pattern
        if (is_hex_silence_pattern(data + i, 16)) {
            result->pattern_type = PATTERN_SILENCE;
            result->offset = i;
            return 1;
        }
        
        // Check for silence-to-tone transition
        if (is_silence_to_tone_transition(data + i, 16)) {
            result->pattern_type = PATTERN_SILENCE_TO_TONE;
            result->offset = i;
            return 1;
        }
    }
    
    return 0;  // No pattern found
}

#endif // AUDIO_PATTERNS_H