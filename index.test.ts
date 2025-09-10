/// <reference types="./fastify.d.ts" />

import { type DecryptedToken, extractTruesignTokenFromHeader, extractTruesignTokenFromQuery, getTruesignHook, TruesignHookConfig } from './index';

function makeMockFastifyRequest(
  {
    headers = {},
    query = {},
  }: {
    headers?: FastifyRequest['headers'];
    query?: FastifyRequest['query'];
  } = {},
): FastifyRequest {
  return {
    headers,
    query,
  } as unknown as FastifyRequest;
}

function makeMockFastifyReply(): FastifyReply {
  const mockReply = {
    code: jest.fn((): FastifyReply => mockReply),
    send: jest.fn(),
  };

  return mockReply;
}

describe('`encryptionKey`', () => {
  test('Not allowing empty', () => {
    const config: TruesignHookConfig = {
      shouldAcceptToken: () => false,
      encryptionKey: '',
    }
    expect(() => getTruesignHook(config)).toThrow('`encryptionKey` is required when `allowUnauthenticated` is false');
  });

  test('Allowing empty if unauthenticated are allowed', () => {
    const config: TruesignHookConfig = {
      allowUnauthenticated: true,
      shouldAcceptToken: () => false,
      encryptionKey: '',
    }
    expect(() => getTruesignHook(config)).not.toThrow();
  });
});

describe('Successful authentication', () => {
  test('By query param', () => {
    const config: TruesignHookConfig = {
      encryptionKey: 'foo',
      decryptFunction: () => ({} as unknown as DecryptedToken),
    }
    const mockNext = jest.fn();
    const mockReply = makeMockFastifyReply();
    const spyCode = jest.spyOn(mockReply, 'code');
    const mockRequest = makeMockFastifyRequest({
      query: {
        'ts-token': 'jarl',
      },
    });

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, mockNext);
    expect(spyCode).not.toBeCalled();
    expect(mockNext).toBeCalledWith();
  });

  test('By header', () => {
    const config: TruesignHookConfig = {
      encryptionKey: 'foo',
      decryptFunction: () => ({} as unknown as DecryptedToken),
    }
    const mockNext = jest.fn();
    const mockReply = makeMockFastifyReply();
    const spyCode = jest.spyOn(mockReply, 'code');
    const mockRequest = makeMockFastifyRequest({
      headers: {
        'x-ts-token': 'jarl',
      },
    });

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, mockNext);
    expect(spyCode).not.toBeCalled();
    expect(mockNext).toBeCalledWith();
  });
});

describe('Failed authentication (401)', () => {
  test('If the token is not provided', () => {
    const config: TruesignHookConfig = {
      shouldAcceptToken: () => false,
      encryptionKey: 'foo',
    }
    const mockNext = jest.fn();
    const mockReply = makeMockFastifyReply();
    const spyCode = jest.spyOn(mockReply, 'code');
    const mockRequest = makeMockFastifyRequest();

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, mockNext);
    expect(spyCode).toBeCalledWith(401);
    expect(mockNext).not.toBeCalled();
  });

  test('If the token could not be decrypted', () => {
    const config: TruesignHookConfig = {
      encryptionKey: 'foo',
      decryptFunction: () => null,
    }
    const mockNext = jest.fn();
    const mockReply = makeMockFastifyReply();
    const spyCode = jest.spyOn(mockReply, 'code');
    const mockRequest = makeMockFastifyRequest({
      query: {
        'ts-token': 'this-token-will-not-decrypt',
      },
    });

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, mockNext);
    expect(spyCode).toBeCalledWith(401);
    expect(mockNext).not.toBeCalled();
  });

  test('If `shouldAcceptToken` resolves to false', () => {
    const config: TruesignHookConfig = {
      shouldAcceptToken: () => false,
      encryptionKey: 'foo',
      decryptFunction: () => ({} as unknown as DecryptedToken),
    }
    const mockNext = jest.fn();
    const mockReply = makeMockFastifyReply();
    const spyCode = jest.spyOn(mockReply, 'code');
    const mockRequest = makeMockFastifyRequest({
      query: {
        'ts-token': 'jarl',
      },
    });

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, mockNext);
    expect(spyCode).toBeCalledWith(401);
    expect(mockNext).not.toBeCalled();
  });
});

describe('Token extraction', () => {
  test('Extracting from query param', () => {
    const decryptMock = jest.fn(() => ({} as unknown as DecryptedToken));

    const config: TruesignHookConfig = {
      encryptionKey: 'foo',
      decryptFunction: decryptMock,
    };

    const mockReply = makeMockFastifyReply();
    const mockRequest = makeMockFastifyRequest({
      query: {
        'ts-token': 'FAKE_TS_TOKEN',
      },
    });

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, () => { });

    expect(decryptMock).toBeCalledWith('foo', 'FAKE_TS_TOKEN');
  });

  test('Extracting from header', () => {
    const decryptMock = jest.fn(() => ({} as unknown as DecryptedToken));

    const config: TruesignHookConfig = {
      encryptionKey: 'foo',
      decryptFunction: decryptMock,
    };

    const mockReply = makeMockFastifyReply();
    const mockRequest = makeMockFastifyRequest({
      headers: {
        'x-ts-token': 'FAKE_TS_TOKEN',
      },
    });

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, () => { });

    expect(decryptMock).toBeCalledWith('foo', 'FAKE_TS_TOKEN');
  });

  test('Preferring query param over header', () => {
    const decryptMock = jest.fn(() => ({} as unknown as DecryptedToken));

    const config: TruesignHookConfig = {
      encryptionKey: 'foo',
      decryptFunction: decryptMock,
    };

    const mockReply = makeMockFastifyReply();
    const mockRequest = makeMockFastifyRequest({
      query: {
        'ts-token': 'FAKE_TS_TOKEN_FROM_QUERY',
      },
      headers: {
        'x-ts-token': 'FAKE_TS_TOKEN_FROM_HEADER',
      },
    });

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, () => { });

    expect(decryptMock).toBeCalledWith('foo', 'FAKE_TS_TOKEN_FROM_QUERY');
  });

  test('Custom query param', () => {
    const decryptMock = jest.fn(() => ({} as unknown as DecryptedToken));

    const config: TruesignHookConfig = {
      encryptionKey: 'foo',
      extractToken: extractTruesignTokenFromQuery('ts-token-test-param'),
      decryptFunction: decryptMock,
    };

    const mockReply = makeMockFastifyReply();
    const mockRequest = makeMockFastifyRequest({
      query: {
        'ts-token-test-param': 'FAKE_CUSTOM_TS_TOKEN',
      },
    });

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, () => { });

    expect(decryptMock).toBeCalledWith('foo', 'FAKE_CUSTOM_TS_TOKEN');
  });

  test('Custom header', () => {
    const decryptMock = jest.fn(() => ({} as unknown as DecryptedToken));

    const config: TruesignHookConfig = {
      encryptionKey: 'foo',
      extractToken: extractTruesignTokenFromHeader('x-ts-token-test-header'),
      decryptFunction: decryptMock,
    };

    const mockReply = makeMockFastifyReply();
    const mockRequest = makeMockFastifyRequest({
      headers: {
        'x-ts-token-test-header': 'FAKE_CUSTOM_TS_TOKEN',
      },
    });

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, () => { });

    expect(decryptMock).toBeCalledWith('foo', 'FAKE_CUSTOM_TS_TOKEN');
  });
});

describe('`allowUnauthenticated`', () => {
  test('Token not provided', () => {
    const config: TruesignHookConfig = {
      allowUnauthenticated: true,
      encryptionKey: 'foo',
      decryptFunction: () => ({} as unknown as DecryptedToken),
    }
    const mockNext = jest.fn();
    const mockReply = makeMockFastifyReply();
    const spyCode = jest.spyOn(mockReply, 'code');
    const mockRequest = makeMockFastifyRequest();

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, mockNext);
    expect(spyCode).not.toBeCalled();
    expect(mockNext).toBeCalledWith();
  });

  test('Token failed to decrypt', () => {
    const config: TruesignHookConfig = {
      allowUnauthenticated: true,
      encryptionKey: '',
      decryptFunction: () => null
    }
    const mockNext = jest.fn();
    const mockReply = makeMockFastifyReply();
    const spyCode = jest.spyOn(mockReply, 'code');
    const mockRequest = makeMockFastifyRequest({
      query: {
        'ts-token': '123',
      },
    });

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, mockNext);
    expect(spyCode).not.toBeCalled();
    expect(mockNext).toBeCalledWith();
  });

  test('Token not accepted by `shouldAcceptToken`', () => {
    const config: TruesignHookConfig = {
      allowUnauthenticated: true,
      shouldAcceptToken: () => false,
      encryptionKey: 'foo',
      decryptFunction: () => ({} as unknown as DecryptedToken),
    }
    const mockNext = jest.fn();
    const mockReply = makeMockFastifyReply();
    const spyCode = jest.spyOn(mockReply, 'code');
    const mockRequest = makeMockFastifyRequest({
      query: {
        'ts-token': 'jarl',
      },
    });

    const hook = getTruesignHook(config);
    hook(mockRequest, mockReply, mockNext);
    expect(spyCode).not.toBeCalled();
    expect(mockNext).toBeCalledWith();
  });
});
