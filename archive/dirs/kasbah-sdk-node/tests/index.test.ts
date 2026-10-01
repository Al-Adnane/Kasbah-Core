/**
 * Tests for Kasbah Node.js SDK
 */

import { KasbahClient, DetectionResult } from '../src/index';
import axios, { AxiosError } from 'axios';
import * as fs from 'fs/promises';

jest.mock('axios');
jest.mock('fs/promises');

const mockedAxios = axios as jest.Mocked<typeof axios>;
const mockedFs = fs as jest.Mocked<typeof fs>;

describe('DetectionResult', () => {
  it('should create a detection result', () => {
    const result: DetectionResult = {
      verdict: 'deepfake',
      confidence: 0.95,
      confidence_level: 'very_high',
      processing_time_ms: 250,
      indicators: [],
    };

    expect(result.verdict).toBe('deepfake');
    expect(result.confidence).toBe(0.95);
    expect(result.confidence_level).toBe('very_high');
  });

  it('should include optional properties', () => {
    const result: DetectionResult = {
      verdict: 'authentic',
      confidence: 0.92,
      confidence_level: 'very_high',
      processing_time_ms: 180,
      spatial_score: 0.88,
      attributed_generator: 'midjourney_v5',
      generator_confidence: 0.87,
      ethics_permissible: true,
      ethics_score: 0.91,
      indicators: ['no_artifacts', 'natural_lighting'],
    };

    expect(result.spatial_score).toBe(0.88);
    expect(result.attributed_generator).toBe('midjourney_v5');
    expect(result.ethics_permissible).toBe(true);
    expect(result.indicators.length).toBe(2);
  });
});

describe('KasbahClient', () => {
  let client: KasbahClient;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup mock axios instance
    const mockAxiosInstance = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
      defaults: { headers: { common: {} } },
      interceptors: {
        request: { use: jest.fn(), eject: jest.fn() },
        response: { use: jest.fn(), eject: jest.fn() }
      }
    };
    
    (mockedAxios.create as jest.Mock).mockReturnValue(mockAxiosInstance);
    
    client = new KasbahClient({ apiKey: 'test-key' });
  });

  describe('constructor', () => {
    it('should create a client with default config', () => {
      const newClient = new KasbahClient({ apiKey: 'test-key' });
      expect(newClient['apiKey']).toBe('test-key');
      expect(newClient['baseUrl']).toBe('https://api.bekasbah.com');
      expect(newClient['timeout']).toBe(30000);
    });

    it('should create a client with custom config', () => {
      const newClient = new KasbahClient({
        apiKey: 'custom-key',
        baseUrl: 'https://custom.api.com',
        timeout: 60000,
      });
      expect(newClient['apiKey']).toBe('custom-key');
      expect(newClient['baseUrl']).toBe('https://custom.api.com');
      expect(newClient['timeout']).toBe(60000);
    });

    it('should set correct authorization header', () => {
      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer test-key',
            'User-Agent': 'kasbah-node/2.0.0',
          }),
        })
      );
    });
  });

  describe('detectImage', () => {
    it('should detect deepfakes in an image', async () => {
      const mockResponse = {
        data: {
          verdict: 'deepfake',
          confidence: 0.95,
          confidence_level: 'very_high',
          processing_time_ms: 250,
          indicators: [],
        },
      };

      mockedFs.access.mockResolvedValue(undefined);
      (client['client'].post as jest.Mock).mockResolvedValue(mockResponse);

      const result = await client.detectImage('/path/to/image.jpg');

      expect(result.verdict).toBe('deepfake');
      expect(result.confidence).toBe(0.95);
      expect(mockedFs.access).toHaveBeenCalledWith('/path/to/image.jpg');
    });

    it('should handle detection options', async () => {
      const mockResponse = {
        data: {
          verdict: 'authentic',
          confidence: 0.92,
          confidence_level: 'very_high',
          processing_time_ms: 180,
          indicators: [],
        },
      };

      mockedFs.access.mockResolvedValue(undefined);
      (client['client'].post as jest.Mock).mockResolvedValue(mockResponse);

      const result = await client.detectImage('/path/to/image.jpg', {
        includeAttribution: false,
        includeEthics: false,
      });

      expect(result.verdict).toBe('authentic');
      expect((client['client'].post as jest.Mock).mock.calls[0][1]).toEqual(
        expect.objectContaining({
          include_attribution: false,
          include_ethics: false,
        })
      );
    });

    it('should throw error if file does not exist', async () => {
      const fileNotFoundError = new Error('File not found');
      (fileNotFoundError as any).code = 'ENOENT';
      (fileNotFoundError as any).path = '/invalid/path.jpg';

      mockedFs.access.mockRejectedValue(fileNotFoundError);

      await expect(client.detectImage('/invalid/path.jpg')).rejects.toThrow(
        'File not found'
      );
    });

    it('should handle API errors', async () => {
      mockedFs.access.mockResolvedValue(undefined);

      const apiError: AxiosError = {
        response: {
          status: 401,
          data: { error: 'Invalid API key' },
        } as any,
      } as AxiosError;

      (client['client'].post as jest.Mock).mockRejectedValue(apiError);

      await expect(client.detectImage('/path/to/image.jpg')).rejects.toThrow(
        'Unauthorized'
      );
    });
  });

  describe('detectVideo', () => {
    it('should detect deepfakes in a video', async () => {
      const mockResponse = {
        data: {
          verdict: 'authentic',
          confidence: 0.88,
          confidence_level: 'high',
          processing_time_ms: 1500,
          indicators: [],
        },
      };

      mockedFs.access.mockResolvedValue(undefined);
      (client['client'].post as jest.Mock).mockResolvedValue(mockResponse);

      const result = await client.detectVideo('/path/to/video.mp4');

      expect(result.verdict).toBe('authentic');
      expect(result.processing_time_ms).toBe(1500);
    });
  });

  describe('detectAudio', () => {
    it('should detect voice clones in audio', async () => {
      const mockResponse = {
        data: {
          verdict: 'deepfake',
          confidence: 0.92,
          confidence_level: 'very_high',
          processing_time_ms: 800,
          indicators: [],
        },
      };

      mockedFs.access.mockResolvedValue(undefined);
      (client['client'].post as jest.Mock).mockResolvedValue(mockResponse);

      const result = await client.detectAudio('/path/to/audio.wav');

      expect(result.verdict).toBe('deepfake');
      expect(mockedFs.access).toHaveBeenCalledWith('/path/to/audio.wav');
    });
  });

  describe('detectFromBase64', () => {
    it('should detect from base64 encoded image', async () => {
      const mockResponse = {
        data: {
          verdict: 'deepfake',
          confidence: 0.90,
          confidence_level: 'very_high',
          processing_time_ms: 300,
          indicators: [],
        },
      };

      (client['client'].post as jest.Mock).mockResolvedValue(mockResponse);

      const base64Data = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
      const result = await client.detectFromBase64(base64Data, 'image');

      expect(result.verdict).toBe('deepfake');
      expect((client['client'].post as jest.Mock).mock.calls[0][0]).toBe('/detect/image');
      expect((client['client'].post as jest.Mock).mock.calls[0][1]).toEqual({
        data_base64: base64Data,
      });
    });

    it('should support video and audio base64', async () => {
      const mockResponse = {
        data: {
          verdict: 'authentic',
          confidence: 0.85,
          confidence_level: 'high',
          processing_time_ms: 400,
          indicators: [],
        },
      };

      (client['client'].post as jest.Mock).mockResolvedValue(mockResponse);

      const base64Data = 'audio_base64_data';
      await client.detectFromBase64(base64Data, 'audio');

      expect((client['client'].post as jest.Mock).mock.calls[0][0]).toBe('/detect/audio');
    });
  });

  describe('getGeneratorInfo', () => {
    it('should retrieve generator information', async () => {
      const mockResponse = {
        data: {
          name: 'midjourney_v5',
          type: 'image',
          vendor: 'Midjourney',
          version: '5.0',
          confidence_baseline: 0.93,
          signatures: ['artifact1'],
        },
      };

      (client['client'].get as jest.Mock).mockResolvedValue(mockResponse);

      const result = await client.getGeneratorInfo('midjourney_v5');

      expect(result.name).toBe('midjourney_v5');
      expect(result.confidence_baseline).toBe(0.93);
      expect((client['client'].get as jest.Mock).mock.calls[0][0]).toBe('/generators/midjourney_v5');
    });
  });

  describe('listGenerators', () => {
    it('should list all generators', async () => {
      const mockResponse = {
        data: {
          generators: ['midjourney_v5', 'dalle3', 'stable_diffusion_3', 'flux'],
        },
      };

      (client['client'].get as jest.Mock).mockResolvedValue(mockResponse);

      const result = await client.listGenerators();

      expect(result).toEqual(['midjourney_v5', 'dalle3', 'stable_diffusion_3', 'flux']);
      expect(result.length).toBe(4);
    });

    it('should filter by media type', async () => {
      const mockResponse = {
        data: {
          generators: ['elevenlabs', 'resemble_ai'],
        },
      };

      (client['client'].get as jest.Mock).mockResolvedValue(mockResponse);

      const result = await client.listGenerators('audio');

      expect(result.length).toBe(2);
      expect((client['client'].get as jest.Mock).mock.calls[0][1]).toEqual({
        params: { type: 'audio' },
      });
    });
  });

  describe('getCalibrationStats', () => {
    it('should get calibration stats for a domain', async () => {
      const mockResponse = {
        data: {
          domain: 'image_synthesis',
          accuracy: 0.95,
          confidence_multiplier: 1.02,
          threshold_adjustment: 0.05,
        },
      };

      (client['client'].get as jest.Mock).mockResolvedValue(mockResponse);

      const result = await client.getCalibrationStats('image_synthesis');

      expect(result.domain).toBe('image_synthesis');
      expect(result.accuracy).toBe(0.95);
    });
  });

  describe('evaluateEthics', () => {
    it('should evaluate ethics of detection result', async () => {
      const mockResponse = {
        data: {
          permissible: true,
          ethical_score: 0.89,
          maqasid_scores: {
            hifz_nafs: 0.90,
            hifz_din: 0.85,
          },
        },
      };

      (client['client'].post as jest.Mock).mockResolvedValue(mockResponse);

      const detection: DetectionResult = {
        verdict: 'deepfake',
        confidence: 0.95,
        confidence_level: 'very_high',
        processing_time_ms: 250,
        indicators: [],
      };

      const result = await client.evaluateEthics(detection);

      expect(result.permissible).toBe(true);
      expect(result.ethical_score).toBe(0.89);
    });
  });

  describe('healthCheck', () => {
    it('should check API health', async () => {
      const mockResponse = {
        data: {
          status: 'healthy',
          version: '2.0.0',
        },
      };

      (client['client'].get as jest.Mock).mockResolvedValue(mockResponse);

      const result = await client.healthCheck();

      expect(result.status).toBe('healthy');
      expect(result.version).toBe('2.0.0');
      expect((client['client'].get as jest.Mock).mock.calls[0][0]).toBe('/health');
    });
  });

  describe('getAccount', () => {
    it('should get account information', async () => {
      const mockResponse = {
        data: {
          account_id: 'acc_123',
          tier: 'pro',
          api_calls_remaining: 9500,
        },
      };

      (client['client'].get as jest.Mock).mockResolvedValue(mockResponse);

      const result = await client.getAccount();

      expect(result.account_id).toBe('acc_123');
      expect(result.tier).toBe('pro');
    });
  });

  describe('getUsageStats', () => {
    it('should get usage statistics', async () => {
      const mockResponse = {
        data: {
          total_calls: 500,
          calls_this_month: 250,
          calls_remaining: 9750,
        },
      };

      (client['client'].get as jest.Mock).mockResolvedValue(mockResponse);

      const result = await client.getUsageStats();

      expect(result.total_calls).toBe(500);
      expect(result.calls_remaining).toBe(9750);
    });
  });

  describe('error handling', () => {
    it('should handle 401 unauthorized', async () => {
      mockedFs.access.mockResolvedValue(undefined);

      const apiError: AxiosError = {
        response: {
          status: 401,
          data: { error: 'Invalid API key' },
        } as any,
      } as AxiosError;

      (client['client'].post as jest.Mock).mockRejectedValue(apiError);

      await expect(client.detectImage('/path/to/image.jpg')).rejects.toThrow(
        'Unauthorized: Invalid API key'
      );
    });

    it('should handle 403 forbidden', async () => {
      mockedFs.access.mockResolvedValue(undefined);

      const apiError: AxiosError = {
        response: {
          status: 403,
          data: { error: 'Access denied' },
        } as any,
      } as AxiosError;

      (client['client'].post as jest.Mock).mockRejectedValue(apiError);

      await expect(client.detectImage('/path/to/image.jpg')).rejects.toThrow(
        'Forbidden: Access denied'
      );
    });

    it('should handle 429 rate limit', async () => {
      mockedFs.access.mockResolvedValue(undefined);

      const apiError: AxiosError = {
        response: {
          status: 429,
          data: { error: 'Rate limit exceeded' },
        } as any,
      } as AxiosError;

      (client['client'].post as jest.Mock).mockRejectedValue(apiError);

      await expect(client.detectImage('/path/to/image.jpg')).rejects.toThrow(
        'Rate limit exceeded'
      );
    });

    it('should handle 500 server error', async () => {
      mockedFs.access.mockResolvedValue(undefined);

      const apiError: AxiosError = {
        response: {
          status: 500,
          data: { error: 'Internal server error' },
        } as any,
      } as AxiosError;

      (client['client'].post as jest.Mock).mockRejectedValue(apiError);

      await expect(client.detectImage('/path/to/image.jpg')).rejects.toThrow(
        'Server error:'
      );
    });

    it('should handle network errors', async () => {
      mockedFs.access.mockResolvedValue(undefined);

      const networkError = new Error('Network error');
      (networkError as any).request = true;

      (client['client'].post as jest.Mock).mockRejectedValue(networkError);

      await expect(client.detectImage('/path/to/image.jpg')).rejects.toThrow(
        'No response from server'
      );
    });
  });
});
