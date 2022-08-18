const PUBLIC_KEY = Buffer.from(
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoYkGj9wOdxlP4+ho/QqqLQ+zaiQ9805fbJo8k1KLIlgYRLkeCDCMFiYgmJnW6v+fbKgX/s5J1GRBB4unMAgoj30Y94bcEF6jcBGZ+DO+m3bs+T8KXtPiL4dG/QVhW+wCPwDVgy+dZUwBlfoA9gLkWivN4QxpZdFxoX6BjZ+ewn+FmguyaiDawmt9NPxV5nIN85/I/Vjo2jstx5qhs09Y4+PCjHX5H8raDsc7+CNP6RuOCzegJXIvsOMGebfZD41fSYB8HpZS6r+B08IQLzQ8MUfnrQo3cLMqBNHf+joke62IybzQYjY/iBWDAzgQcDxD+TMduALTaPXJw4ghwqmxtQIDAQAB',
  'base64'
);

type TokenSteps = {
  PAYLOAD: Record<string, any>;
  HEADER_AND_PAYLOAD: string;
  SIGNATURE: Buffer;
  FULL_TOKEN: string;
};

const assembleToken = (steps: TokenSteps) => {
  return `${steps.HEADER_AND_PAYLOAD}.${steps.SIGNATURE.toString('base64url')}`;
};

const NORMAL: TokenSteps = {
  PAYLOAD: {
    test: 'Hello World!',
  },
  HEADER_AND_PAYLOAD:
    'eyJhbGciOiJSU0FTU0FfUFNTX1NIQV8yNTYiLCJ0eXAiOiJKV1QifQ.eyJ0ZXN0IjoiSGVsbG8gV29ybGQhIn0',
  SIGNATURE: Buffer.from(
    'TIQIZr4pyh/xyJW1EGiYvOAnjkC4rEqgIVaRyr9+2Lr2Yl/XwLyC5dVIbh2yG19LYCLvGqLn2Z1shZdf4maqAAUjjs1zacpeH6NSpcTSMNi/hWRL+ZHiD7bjGFWH2S14LkD0CLNa3ka6utf/xpvrpVhhMKOcyk7KPOomgRePDlpXPQYZ9MxqbGF1IJamC2spVXzVL/oLk5QD36HpNfBpA1rZhsjBaazca5US4ydLwddx76rYz/px+UnwN5tNeT1E9BQUTpgktGqm7vca4D6CUAM59p9l6vYsp/g4rdpoKGPP+F+cN59zj6pC7q83F7UDkiZUxrrrfBZsc9yUvCf/Dw==',
    'base64'
  ),
  FULL_TOKEN: '',
};

NORMAL.FULL_TOKEN = assembleToken(NORMAL);

const EXPIRES_IN: TokenSteps = {
  PAYLOAD: {
    test: 'Hello World!',
  },
  HEADER_AND_PAYLOAD:
    'eyJhbGciOiJSU0FTU0FfUFNTX1NIQV8yNTYiLCJ0eXAiOiJKV1QifQ.eyJ0ZXN0IjoiSGVsbG8gV29ybGQhIiwiZXhwIjoxNTc3ODM2ODAxfQ',
  SIGNATURE: Buffer.from(
    'aiiZPJYDqwCZ2yZoFvMZtbcGHUbLjrNq86D7sfixgb6nuQgfR+QmSER9ab4J73j9GPXgnvq4xVqcUeyaH6yZMbkLyQXhSTZFheFoyuI8KykZ8cMvT4VF238loZ6CR/u6gukB/4CNtF+awuOsDqTWNmqbhZrEDBR8UmKLbJwPt26hq22ugcdMJooBUMdKzfePMgTtKvg03/41Xeouiji7B7AI0p2OEINeyEt7d3oNhWSBUVrddo8yQoJRU3Nz6J5WjxSv13zvyzxLDHwGeN2VX6bSHtgkORy8p8dnlqXlBrRFQc4KNW0eC7hf+yDRwNGcScDIocEhwuxBKIv69Bb/8Q==',
    'base64'
  ),
  FULL_TOKEN: '',
};

EXPIRES_IN.FULL_TOKEN = assembleToken(EXPIRES_IN);

export { PUBLIC_KEY, NORMAL, EXPIRES_IN };
