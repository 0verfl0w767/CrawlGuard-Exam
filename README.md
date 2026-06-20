# CrawlGuard-Exam

단순한 API 재생 공격과 "요청 하나 복사해서 계속 쓰는" 형태의 크롤링을
어렵게 만드는 Express 기반 프로젝트입니다.

## 개요

이 프로젝트의 보호 API는 아래 4단계로 막습니다.

1. 클라이언트가 먼저 PoW 챌린지를 요청해야 합니다.
2. 받은 챌린지를 풀고 검증해야 합니다.
3. 서버는 현재 세션, IP, User-Agent에 묶인 액세스 토큰을 발급합니다.
4. 보호 API를 호출할 때마다 새로운 요청 서명 헤더를 같이 보내야 합니다.

추가로 아래 정책도 함께 적용됩니다.

- 액세스 토큰 기본 수명은 10초
- 보호 API 성공 시 토큰 자동 회전
- 이전 토큰은 회전 후 5초만 grace 허용
- 완전히 같은 signed request 재전송은 nonce 재사용으로 차단

## 엔드포인트

| Method | Path                     | 설명                     | 그냥 요청 시 결과    |
| ------ | ------------------------ | ------------------------ | -------------------- |
| `GET`  | `/health`                | 헬스 체크                | `200`                |
| `GET`  | `/api/test/open-feed`    | 비교용 오픈 API          | `200`                |
| `GET`  | `/api/challenge`         | PoW 챌린지 발급          | `200`                |
| `POST` | `/api/challenge/verify`  | 챌린지 검증 및 토큰 발급 | 유효하면 `200`       |
| `GET`  | `/api/test/guarded-feed` | 보호 API                 | 조건 불충족 시 `401` |
| `GET`  | `/api/protected/feed`    | 보호 API 별칭            | 조건 불충족 시 `401` |

## 보호 API 호출 흐름

### 1. 직접 호출은 실패해야 함

`GET /api/test/guarded-feed`

이 단계에서는 아래처럼 나와야 정상입니다.

- `401`
- Bearer token 없음
- 요청 서명 헤더 없음

### 2. 챌린지 요청

`GET /api/challenge`

응답에는 아래 정보가 포함됩니다.

- `challengeId`
- `salt`
- `difficulty`
- 만료 시간

클라이언트는 아래 값을 만족하는 `nonce`를 찾아야 합니다.

```text
sha256(challengeId:salt:nonce)
```

해시 앞부분이 난이도(`difficulty`)만큼 `0`으로 시작하면 성공입니다.

### 3. 챌린지 검증

`POST /api/challenge/verify`

요청 바디:

```json
{
  "challengeId": "string",
  "nonce": "string"
}
```

응답에는 아래 정보가 들어옵니다.

- `accessToken`
- `expiresAt`
- `tokenPolicy`
- `requestSigning`

### 4. 보호 API는 매번 서명해서 호출해야 함

`GET /api/test/guarded-feed`를 호출할 때는 아래 헤더가 모두 있어야 합니다.

- `Authorization: Bearer <accessToken>`
- `x-cg-timestamp`
- `x-cg-nonce`
- `x-cg-signature`

서명 입력 포맷은 아래와 같습니다.

```text
METHOD
PATH
bodySha256
timestamp
nonce
```

서명 규칙:

```text
x-cg-signature = HMAC-SHA256(accessToken, canonicalInput)
```

`GET` 요청에서는 body가 없으므로 `bodySha256`은 빈 문자열의 SHA-256입니다.

### 5. 성공하면 토큰이 회전함

보호 API가 성공하면 응답에 아래 필드가 내려옵니다.

- `rotation.nextAccessToken`
- `rotation.nextExpiresAt`
- `rotation.previousTokenGraceUntil`

클라이언트는 기존 토큰 대신 `rotation.nextAccessToken`으로 바로 갈아타야 합니다.

## 토큰 정책

현재 기본 정책은 아래와 같습니다.

| 항목                    | 기본값      |
| ----------------------- | ----------- |
| 챌린지 TTL              | `120000 ms` |
| 액세스 토큰 TTL         | `10000 ms`  |
| 회전 후 이전 토큰 grace | `5000 ms`   |
| 요청 서명 유효 시간창   | `30000 ms`  |

의미는 아래와 같습니다.

- 토큰을 뺏겨도 오래 못 씀
- 토큰이 있어도 요청마다 새 서명이 필요함
- 똑같은 signed request 재전송은 막힘
- 이전 토큰도 아주 잠깐만 살아 있음

## 로컬 실행

```bash
npm install
npm start
```

브라우저에서 아래 주소를 엽니다.

```text
http://localhost:3000
```

페이지에서는 아래 내용을 문서형으로 확인할 수 있습니다.

- 직접 요청 시 보호 API 실패
- 챌린지 발급 결과
- 검증 결과
- 마지막 signed header 값
- 회전된 최신 토큰 상태

## 로컬에서 직접 확인하는 순서

1. `/` 페이지 열기
2. `Try direct request` 클릭
3. 보호 API가 `401`인지 확인
4. `Run challenge flow` 클릭
5. 보호 API가 성공하는지 확인
6. `Call guarded API with signed request` 다시 클릭
7. 토큰이 또 회전하는지 확인

## 테스트

실행:

```bash
npm test
```

현재 테스트는 아래를 확인합니다.

- 오픈 API는 직접 호출이 성공하는지
- 보호 API는 직접 호출이 실패하는지
- 챌린지 검증 후 보호 API가 열리는지
- signed request 재전송이 nonce 재사용으로 막히는지
- 이전 토큰이 잠깐 grace로 허용되다가 만료되는지
- User-Agent가 바뀐 토큰 재사용이 실패하는지

## 환경변수

| 변수명                        | 기본값       | 설명                         |
| ----------------------------- | ------------ | ---------------------------- |
| `PORT`                        | `3000`       | 서버 포트                    |
| `CHALLENGE_DIFFICULTY`        | `4`          | PoW 난이도                   |
| `CHALLENGE_TTL_MS`            | `120000`     | 챌린지 유효 시간             |
| `TOKEN_TTL_MS`                | `10000`      | 액세스 토큰 유효 시간        |
| `ROTATED_TOKEN_GRACE_MS`      | `5000`       | 회전 후 이전 토큰 grace 시간 |
| `REQUEST_SIGNATURE_WINDOW_MS` | `30000`      | 요청 timestamp 허용 시간창   |
| `CHALLENGE_ISSUE_LIMIT`       | `20`         | IP당 챌린지 발급 허용 횟수   |
| `CHALLENGE_ISSUE_WINDOW_MS`   | `60000`      | 챌린지 발급 제한 시간창      |
| `CRAWLGUARD_SECRET`           | 실행 시 랜덤 | 토큰/요청 서명용 HMAC 시크릿 |

## 프로젝트 구조

| 경로                | 역할                               |
| ------------------- | ---------------------------------- |
| `server.js`         | 서버 엔트리포인트                  |
| `src/app.js`        | Express 앱과 라우트                |
| `src/security.js`   | 챌린지, 토큰, 요청 서명, 회전 로직 |
| `public/index.html` | 문서형 데모 UI                     |
| `test/app.test.js`  | 전체 흐름 테스트                   |
