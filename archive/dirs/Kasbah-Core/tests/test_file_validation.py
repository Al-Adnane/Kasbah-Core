"""
Comprehensive test suite for file_validation module
Tests magic bytes verification, file spoofing prevention, and all validation functions
"""

import pytest
from core.security.file_validation import (
    verify_magic_bytes,
    detect_mime_type,
    validate_file_extension,
    validate_file_size,
    sanitize_filename,
    validate_file,
    sanitize_string,
    validate_analysis_result,
    FileValidationResult,
    ValidationResult,
    BLOCKED_EXTENSIONS,
    FILE_SIZE_LIMITS,
)


class TestMagicBytesVerification:
    """Test magic bytes verification to prevent file type spoofing"""

    def test_valid_png_signature(self):
        """Test valid PNG file signature"""
        png_header = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + b'PNG DATA'
        result = verify_magic_bytes(png_header, 'image/png')
        assert result.valid is True
        assert result.detected_mime_type == 'image/png'
        assert result.error is None

    def test_valid_jpeg_signature(self):
        """Test valid JPEG file signature"""
        jpeg_header = bytes([0xFF, 0xD8, 0xFF]) + b'JPEG DATA'
        result = verify_magic_bytes(jpeg_header, 'image/jpeg')
        assert result.valid is True
        assert result.detected_mime_type == 'image/jpeg'

    def test_valid_gif_signature(self):
        """Test valid GIF file signature"""
        gif_header = bytes([0x47, 0x49, 0x46, 0x38]) + b'GIF DATA'
        result = verify_magic_bytes(gif_header, 'image/gif')
        assert result.valid is True
        assert result.detected_mime_type == 'image/gif'

    def test_valid_webp_signature(self):
        """Test valid WebP file signature"""
        webp_header = bytes([0x52, 0x49, 0x46, 0x46]) + b'\x00\x00\x00\x00' + bytes([0x57, 0x45, 0x42, 0x50]) + b'DATA'
        result = verify_magic_bytes(webp_header, 'image/webp')
        assert result.valid is True

    def test_valid_mp3_signature(self):
        """Test valid MP3 file signature (with frame sync mask)"""
        mp3_header = bytes([0xFF, 0xFB]) + b'MP3 DATA'  # 0xFB has frame sync mask
        result = verify_magic_bytes(mp3_header, 'audio/mpeg')
        assert result.valid is True
        assert result.detected_mime_type == 'audio/mpeg'

    def test_invalid_signature_for_claimed_type(self):
        """Test file with wrong signature for claimed type (file type spoofing)"""
        # PNG header claiming to be JPEG
        png_header = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + b'PNG'
        result = verify_magic_bytes(png_header, 'image/jpeg')
        assert result.valid is False
        assert result.code == 'INVALID_SIGNATURE'
        assert 'file type spoofing' in result.error.lower()

    def test_mime_type_mismatch_detection(self):
        """Test detection of MIME type mismatch"""
        # JPEG header claiming to be PNG - needs to be large enough for PNG signature
        jpeg_header = bytes([0xFF, 0xD8, 0xFF]) + b'JPEG' * 10
        result = verify_magic_bytes(jpeg_header, 'image/png')
        assert result.valid is False
        assert result.code == 'INVALID_SIGNATURE'  # Will fail primary signature check
        assert result.detected_mime_type == 'image/jpeg'

    def test_file_too_small(self):
        """Test file too small for signature verification"""
        result = verify_magic_bytes(b'XX', 'image/png')
        assert result.valid is False
        assert result.code == 'FILE_TOO_SMALL'

    def test_unsupported_mime_type(self):
        """Test unsupported MIME type"""
        result = verify_magic_bytes(b'data', 'application/unsupported')
        assert result.valid is False
        assert result.code == 'UNSUPPORTED_MIME_TYPE'


class TestMimeTypeDetection:
    """Test MIME type detection from magic bytes"""

    def test_detect_png(self):
        """Test PNG detection"""
        png_data = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + b'PNG'
        detected = detect_mime_type(png_data)
        assert detected == 'image/png'

    def test_detect_jpeg(self):
        """Test JPEG detection"""
        jpeg_data = bytes([0xFF, 0xD8, 0xFF]) + b'JPEG'
        detected = detect_mime_type(jpeg_data)
        assert detected == 'image/jpeg'

    def test_detect_gif(self):
        """Test GIF detection"""
        gif_data = bytes([0x47, 0x49, 0x46, 0x38]) + b'GIF'
        detected = detect_mime_type(gif_data)
        assert detected == 'image/gif'

    def test_detect_mp3(self):
        """Test MP3 detection"""
        mp3_data = bytes([0xFF, 0xFB]) + b'MP3'
        detected = detect_mime_type(mp3_data)
        assert detected == 'audio/mpeg'

    def test_no_detection_small_file(self):
        """Test no detection for file too small"""
        detected = detect_mime_type(b'XX')
        assert detected is None

    def test_no_detection_unknown_format(self):
        """Test no detection for unknown format"""
        detected = detect_mime_type(b'UNKNOWN_FORMAT_DATA')
        assert detected is None


class TestFileExtensionValidation:
    """Test file extension validation"""

    def test_valid_png_extension(self):
        """Test valid PNG extension"""
        result = validate_file_extension('image.png', 'image/png')
        assert result.valid is True
        assert result.sanitized_value == 'image.png'

    def test_valid_jpeg_extensions(self):
        """Test valid JPEG extensions"""
        for ext in ['image.jpg', 'photo.jpeg', 'pic.jpe']:
            result = validate_file_extension(ext, 'image/jpeg')
            assert result.valid is True

    def test_extension_mismatch(self):
        """Test extension mismatch with MIME type"""
        result = validate_file_extension('image.jpg', 'image/png')
        assert result.valid is False
        assert result.code == 'EXTENSION_MISMATCH'

    def test_blocked_extension(self):
        """Test blocked dangerous extensions"""
        result = validate_file_extension('malware.exe', 'application/octet-stream')
        assert result.valid is False
        assert result.code == 'BLOCKED_EXTENSION'

    def test_missing_extension(self):
        """Test file without extension"""
        result = validate_file_extension('noextension', 'image/png')
        assert result.valid is False
        assert result.code == 'MISSING_EXTENSION'

    def test_unsupported_mime_type(self):
        """Test unsupported MIME type"""
        result = validate_file_extension('file.unknown', 'application/unknown')
        assert result.valid is False
        assert result.code == 'UNSUPPORTED_MIME_TYPE'

    def test_case_insensitive_extension(self):
        """Test case insensitive extension matching"""
        result = validate_file_extension('image.PNG', 'image/png')
        assert result.valid is True

    def test_invalid_filename_characters(self):
        """Test invalid characters in filename"""
        result = validate_file_extension('image\x00.png', 'image/png')
        assert result.valid is False
        assert result.code == 'INVALID_FILENAME'


class TestFileSizeValidation:
    """Test file size validation"""

    def test_valid_small_file(self):
        """Test valid small file size"""
        result = validate_file_size(1024, 'image/png')
        assert result.valid is True

    def test_valid_large_image(self):
        """Test valid large image file"""
        size = 40 * 1024 * 1024  # 40MB < 50MB limit for images
        result = validate_file_size(size, 'image/png')
        assert result.valid is True

    def test_file_too_small(self):
        """Test file below minimum size"""
        result = validate_file_size(50, 'image/png')
        assert result.valid is False
        assert result.code == 'FILE_TOO_SMALL'

    def test_file_exceeds_type_limit(self):
        """Test file exceeding MIME type limit"""
        size = 100 * 1024 * 1024  # 100MB > 50MB limit for images
        result = validate_file_size(size, 'image/png')
        assert result.valid is False
        assert result.code == 'FILE_TOO_LARGE'

    def test_file_exceeds_absolute_limit(self):
        """Test file exceeding absolute limit"""
        size = 600 * 1024 * 1024  # 600MB > 500MB absolute limit
        result = validate_file_size(size, 'image/png')
        assert result.valid is False
        assert result.code == 'FILE_TOO_LARGE'

    def test_video_size_limit(self):
        """Test video size limits (higher than images)"""
        size = 400 * 1024 * 1024  # 400MB < 500MB limit for videos
        result = validate_file_size(size, 'video/mp4')
        assert result.valid is True


class TestFilenameSanitization:
    """Test filename sanitization"""

    def test_normal_filename(self):
        """Test normal filename passes through"""
        result = sanitize_filename('document.pdf')
        assert result == 'document.pdf'

    def test_remove_path_separators(self):
        """Test path traversal prevention"""
        result = sanitize_filename('../../../etc/passwd')
        assert '/' not in result
        assert '\\' not in result

    def test_remove_null_bytes(self):
        """Test null byte removal"""
        result = sanitize_filename('file\x00name.txt')
        assert '\x00' not in result

    def test_remove_control_characters(self):
        """Test control character removal"""
        result = sanitize_filename('file\x01\x02name.txt')
        assert '\x01' not in result
        assert '\x02' not in result

    def test_remove_leading_dots(self):
        """Test removal of leading dots (hidden files)"""
        result = sanitize_filename('...hiddenfile.txt')
        assert not result.startswith('.')

    def test_limit_filename_length(self):
        """Test filename length limitation"""
        long_name = 'a' * 300 + '.txt'
        result = sanitize_filename(long_name)
        assert len(result) <= 255

    def test_preserve_extension_after_trimming(self):
        """Test extension preserved when trimming length"""
        long_name = 'a' * 300 + '.txt'
        result = sanitize_filename(long_name)
        assert result.endswith('.txt')


class TestCompleteFileValidation:
    """Test comprehensive file validation"""

    def test_valid_png_file(self):
        """Test valid PNG file passes all checks"""
        filename = 'image.png'
        size = 1024
        mime_type = 'image/png'
        buffer = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + b'PNG DATA'

        result = validate_file(filename, size, mime_type, buffer)
        assert result.valid is True
        assert result.detected_mime_type == 'image/png'

    def test_file_type_spoofing_detected(self):
        """Test file type spoofing is detected"""
        filename = 'image.png'
        size = 1024
        mime_type = 'image/png'
        buffer = bytes([0xFF, 0xD8, 0xFF]) + b'JPEG DATA'  # JPEG header

        result = validate_file(filename, size, mime_type, buffer)
        assert result.valid is False
        assert result.code == 'INVALID_SIGNATURE'

    def test_invalid_extension_rejected(self):
        """Test invalid extension is rejected"""
        filename = 'image.jpg'  # Wrong extension
        size = 1024
        mime_type = 'image/png'
        buffer = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + b'PNG'

        result = validate_file(filename, size, mime_type, buffer)
        assert result.valid is False

    def test_blocked_extension_rejected(self):
        """Test blocked extensions are rejected"""
        filename = 'malware.exe'
        size = 1024
        mime_type = 'application/octet-stream'
        buffer = b'EXE HEADER'

        result = validate_file(filename, size, mime_type, buffer)
        assert result.valid is False

    def test_file_too_large_rejected(self):
        """Test oversized files are rejected"""
        filename = 'huge_video.mp4'
        size = 600 * 1024 * 1024  # 600MB
        mime_type = 'video/mp4'
        buffer = bytes([0x00, 0x00, 0x00, 0x20]) + b'ftypisom'

        result = validate_file(filename, size, mime_type, buffer)
        assert result.valid is False


class TestStringSanitization:
    """Test string sanitization"""

    def test_normal_string(self):
        """Test normal string passes through"""
        result = sanitize_string("Hello, World!")
        assert result.valid is True
        assert result.sanitized_value == "Hello, World!"

    def test_string_too_long(self):
        """Test string exceeding max length"""
        long_string = "a" * 1001
        result = sanitize_string(long_string, max_length=1000)
        assert result.valid is False
        assert result.code == 'INPUT_TOO_LONG'

    def test_invalid_type(self):
        """Test non-string input"""
        result = sanitize_string(123)
        assert result.valid is False
        assert result.code == 'INVALID_TYPE'

    def test_remove_null_bytes(self):
        """Test null byte removal"""
        result = sanitize_string("hello\x00world")
        assert result.valid is True
        assert '\x00' not in result.sanitized_value


class TestAnalysisResultValidation:
    """Test analysis result validation"""

    def test_valid_analysis_result(self):
        """Test valid analysis result"""
        result_data = {
            'result': 'authentic',
            'confidence': 0.95,
            'analysis': 'This is an authentic image',
            'indicators': ['indicator1', 'indicator2']
        }
        result = validate_analysis_result(result_data)
        assert result.valid is True
        assert result.sanitized_value['confidence'] == 0.95

    def test_invalid_result_value(self):
        """Test invalid result value"""
        result_data = {
            'result': 'maybe',  # Invalid
            'confidence': 0.95,
            'analysis': 'Analysis',
            'indicators': []
        }
        result = validate_analysis_result(result_data)
        assert result.valid is False
        assert result.code == 'INVALID_RESULT_VALUE'

    def test_invalid_confidence(self):
        """Test invalid confidence value"""
        result_data = {
            'result': 'authentic',
            'confidence': 1.5,  # > 1.0
            'analysis': 'Analysis',
            'indicators': []
        }
        result = validate_analysis_result(result_data)
        assert result.valid is False
        assert result.code == 'INVALID_CONFIDENCE'

    def test_empty_indicators_list(self):
        """Test empty indicators list"""
        result_data = {
            'result': 'authentic',
            'confidence': 0.95,
            'analysis': 'Analysis',
            'indicators': []
        }
        result = validate_analysis_result(result_data)
        assert result.valid is True

    def test_invalid_type(self):
        """Test invalid input type"""
        result = validate_analysis_result(None)
        assert result.valid is False
        assert result.code == 'INVALID_FORMAT'


class TestStressScenarios:
    """Stress test scenarios"""

    def test_many_files_rapid_validation(self):
        """Test rapid validation of multiple files"""
        for i in range(100):
            filename = f'image{i}.png'
            buffer = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + b'DATA'
            result = verify_magic_bytes(buffer, 'image/png')
            assert result.valid is True

    def test_malformed_files_rejected(self):
        """Test various malformed files are rejected"""
        test_cases = [
            (b'', 'image/png', 'FILE_TOO_SMALL'),
            (b'X' * 50, 'image/png', 'INVALID_SIGNATURE'),  # Enough data but wrong signature
            (bytes([0xFF, 0xD8, 0xFF]) + b'DATA' * 10, 'image/png', 'INVALID_SIGNATURE'),
        ]

        for buffer, mime_type, expected_code in test_cases:
            result = verify_magic_bytes(buffer, mime_type)
            assert result.valid is False
            assert result.code == expected_code

    def test_all_blocked_extensions_rejected(self):
        """Test all blocked extensions are rejected"""
        for ext in BLOCKED_EXTENSIONS[:10]:  # Test subset
            filename = f'file{ext}'
            result = validate_file_extension(filename, 'application/octet-stream')
            assert result.valid is False
            assert result.code == 'BLOCKED_EXTENSION'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
