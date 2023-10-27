import { getTruesignHook } from './index';

function getMockResponse() {
  return {
    code(n: number) {
      return {
        send() {
          return void 0;
        }
      }
    }
  }
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
      tsToken: '123',
    },
  }

  const hook = getTruesignHook(config);
  hook(mockRequest, mockResponse, mockCb);
  expect(mockCb).toBeCalled();
});

test('Not allowing unauthenticated but passing empty encryptionKey', () => {
  const config = {
    allowUnauthenticated: false,
    shouldAcceptToken: () => false,
    encryptionKey: '',
  }
  const mockCb = jest.fn();
  const mockResponse = getMockResponse(); 
  const mockRequest = {
    query: {
      tsToken: '123',
    },
  }

  const hook = getTruesignHook(config);
  hook(mockRequest, mockResponse, mockCb);
  expect(mockCb).toBeCalled();
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
    query: { },
  }

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
    decryptFunction: () => 'bar',
  }
  const mockCb = jest.fn();
  const mockResponse = getMockResponse(); 
  const spy = jest.spyOn(mockResponse, 'code');
  const mockRequest = {
    query: {
      tsToken: 'jarl',
    },
  }

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
    decryptFunction: () => 'bar',
  }
  const mockCb = jest.fn();
  const mockResponse = getMockResponse(); 
  const spy = jest.spyOn(mockResponse, 'code');
  const mockRequest = {
    query: {
      tsToken: 'jarl',
    },
  }

  const hook = getTruesignHook(config);
  hook(mockRequest, mockResponse, mockCb);
  expect(mockCb).toBeCalled();
});