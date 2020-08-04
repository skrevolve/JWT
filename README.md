# JWT
JWT는 속성정보(claim)를 JSON 데이터 구조로 표현한 토큰이다.   
http Request 헤더에 JSON 토큰을 넣은 후 서버는 별도의 인증없이 헤더에 포함되 있는 JWT정보를 통해 인증한다.   
JSON데이터는 URL-safe 하도록 URL에 포함할 수 있는 문자만으로 만든다.   
JWT는 HMAC알고리즘으 사용하여 비밀키  또는 RSA를 이용한 Public Key/Private Key 쌍으로 서명할 수 있다.   

## JWT와 관련된 표준
![900_JWS_JWE_Banner](https://user-images.githubusercontent.com/41939976/89265820-08c48700-d670-11ea-961d-80113bc990e6.png)
### JWS(Signature)   
- JSON데이터 구조를 사용하는 서명표준   
### JWE(Encryption)   
JSON데이터 구조를 사용하는 암호화 방법   
- JWS는 JSON으로 전자서명하여 URL-safe 문자열로 표현한 것이다.   
- JWE는 JSON으로 암호화하여 URL-safe 문자열로 표현한 것이다.

### URL-safe란?
- URL에 포함될 수 없는 문자를 포함하지 않는 것

### Signature란?
- 서명할때 사용한 키를 사용하여 JSON이 손상되지 않았는지 확인 하는 것

## JWT 토큰 구성
![json-web-token-overview1](https://user-images.githubusercontent.com/41939976/89266708-38c05a00-d671-11ea-812a-c0a3918a02df.png)
JWT는 크게 .으로 구분하여 3 파트로 나뉘어 진다 (Header,Payload,Signature)

#### URL과 URI의 차이
- URL > URI 구조
- URI : 인터넷 상의 자원을 식별하기 위한 문자열의 구성
- URL : 인터넷 상의 자원의 위치와 식별자 (파일의 위치 표시하기 위한)

Base64 인코딩 경우 +, -, /, = 이 포함되지만 JWT는 URI에서 파라미터로 사용할 수 있도록 URL-safe한 Base64url인코딩을 사용한다.

### Header
- 토큰의 타입 + 해시암호화 알고리즘 구조
- 토큰의 타입 : 토큰의 유형(JWT)
- 해시암호화 알고리즘 : HMAC,SHA256 또는 RSA와 같은 해시 알고리즘

### Payload
- 토큰에 담을 속성정보(claim)를 포함하고 있다.
- 이 payload에 담는 정보의 한 조각을 'claim'이라 부르고 이 클레임은 name/value 한쌍으로 이루어져 있다.
- 토큰에는 여러개의 클레임들을 넣을 수 있다.
- 클레임의 정보는 Registered(등록된), Public(공개), Private(비공개) 클레임으로 세 종류가 있다.

### Signature
- secretkey를 포함하여 암호화 되어있다.

## JWT 프로세스
   
![Microservice-With-OAuth](https://user-images.githubusercontent.com/41939976/89267422-2db9f980-d672-11ea-9832-8230218994e9.png)
### MicroService with OAuth
- 기존의 토큰 방식 인증은 모든 서비스 호출에 사용된다
- 서비스를 받기 위해서는 토큰의 유효성을 확인하여 세부 정보를 쿼리해야 한다
- 참조에 의한 호출(By Reference) 형태로 모든 서비스는 항상 상호 작용할때 다시 접속해야 한다   
   
---------------
![Microservice-With-JWT](https://user-images.githubusercontent.com/41939976/89267452-38748e80-d672-11ea-9b33-cd3a4073e6aa.png)
### MicroService with JWT
- 값에 의한 호출이 가능한 토큰방식이다
- 토큰이 필요한 모든 정보를 포함하고 있어 참조(적어도 인증 및 권한 부여를 위해)가 필요없기 때문에 마이크로 서비스 자체에서 유효성 검증을 한다
- 따라서 이것이 JWT의 목적이라 볼 수 있다
----------------
