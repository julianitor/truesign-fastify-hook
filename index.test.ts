/// <reference types="./fastify.d.ts" />

import { type DecryptedToken, getTruesignHook } from './index';

function getMockResponse(): FastifyReply {
  return {
    code(n: number) {
      return {
        send() {
          return void 0;
        }
      }
    }
  } as unknown as FastifyReply;
}

test('Allowing unauthenticated', () => {
  const config = {
    allowUnauthenticated: true,
    shouldAcceptToken: () => false,
    encryptionKey: 'foo',
  }
  const mockCb = jest.fn();
  const mockResponse = getMockResponse();
  const mockRequest = {
    query: {
      'ts-token': '123',
    },
  } as unknown as FastifyRequest;

  const hook = getTruesignHook(config);
  hook(mockRequest, mockResponse, mockCb);
  expect(mockCb).toBeCalled();
});

test('Not allowing empty encryptionKey', () => {
  const config = {
    allowUnauthenticated: false,
    shouldAcceptToken: () => false,
    encryptionKey: '',
  }
  expect(() => getTruesignHook(config)).toThrow();
});

test('Allowing empty encryptionKey if unauthenticated are allowed', () => {
  const config = {
    allowUnauthenticated: true,
    shouldAcceptToken: () => false,
    encryptionKey: '',
  }
  expect(() => getTruesignHook(config)).not.toThrow();
});

test('Response sending 401 if the token is not provided', () => {
  const config = {
    allowUnauthenticated: false,
    shouldAcceptToken: () => false,
    encryptionKey: 'foo',
  }
  const mockCb = jest.fn();
  const mockResponse = getMockResponse();
  const spy = jest.spyOn(mockResponse, 'code');
  const mockRequest = {
    query: {},
  } as unknown as FastifyRequest;

  const hook = getTruesignHook(config);
  hook(mockRequest, mockResponse, mockCb);
  expect(spy).toBeCalledWith(401);
  expect(mockCb).not.toBeCalled();
});

test('Response sending 401 if shouldAcceptToken resolves to false', () => {
  const config = {
    allowUnauthenticated: false,
    shouldAcceptToken: () => false,
    encryptionKey: 'foo',
    decryptFunction: () => ({} as unknown as DecryptedToken),
  }
  const mockCb = jest.fn();
  const mockResponse = getMockResponse();
  const spy = jest.spyOn(mockResponse, 'code');
  const mockRequest = {
    query: {
      'ts-token': 'jarl',
    },
  } as unknown as FastifyRequest;

  const hook = getTruesignHook(config);
  hook(mockRequest, mockResponse, mockCb);
  expect(spy).toBeCalledWith(401);
  expect(mockCb).not.toBeCalled();
});

test('Allowing properly authenticated token', () => {
  const config = {
    allowUnauthenticated: false,
    shouldAcceptToken: () => true,
    encryptionKey: 'foo',
    decryptFunction: () => ({} as unknown as DecryptedToken),
  }
  const mockCb = jest.fn();
  const mockResponse = getMockResponse();
  const spy = jest.spyOn(mockResponse, 'code');
  const mockRequest = {
    query: {
      'ts-token': 'jarl',
    },
  } as unknown as FastifyRequest;

  const hook = getTruesignHook(config);
  hook(mockRequest, mockResponse, mockCb);
  expect(mockCb).toBeCalled();
});