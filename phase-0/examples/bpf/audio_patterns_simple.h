// audio_patterns_simple.h - Simplified audio patterns for eBPF detection
#ifndef AUDIO_PATTERNS_SIMPLE_H
#define AUDIO_PATTERNS_SIMPLE_H

// Pattern types
#define PATTERN_SILENCE         1
#define PATTERN_SOUND           2

// Simple check for hex silence pattern "00000000" (4 bytes of silence)
static __always_inline int check_for_silence(const char *data, void *data_end) {
    // Need at least 8 hex chars
    if (data + 8 > (char *)data_end)
        return 0;
    
    // Check if all 8 chars are '0'
    if (data[0] == '0' && data[1] == '0' && 
        data[2] == '0' && data[3] == '0' &&
        data[4] == '0' && data[5] == '0' && 
        data[6] == '0' && data[7] == '0') {
        return 1;
    }
    
    return 0;
}

#endif // AUDIO_PATTERNS_SIMPLE_H