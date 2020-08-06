스프링 공부하다 인증 관련해서 oAuth를 많이 사용하게 됐는데     
회사에서 마이크로서비스 프로젝트를 시작하게 되면서 자연스레 JWT에 대해 공부하게 됐습니다   
개념만 알고있던 JWT에 대해 공부도 되고 보안적인 문제점이 있을까 생각하는 계기가 되어 글 작성해봅니다   

# JWT (JSON Web Token)
주로 서비스에 대한 인증이나 CSRF 토큰등에 사용될 수 있겠다      
JWT는 속성정보(claim)를 JSON 데이터 구조로 표현한 토큰이다   
http Request 헤더에 JSON 토큰을 넣은 후 서버는 별도의 인증없이 헤더에 포함되 있는 JWT정보를 통해 인증한다    
JSON데이터는 URL-safe 하도록 URL에 포함할 수 있는 문자만으로 만든다   
JWT는 HMAC알고리즘을 사용하여 비밀키  또는 RSA를 이용한 Public Key/Private Key 쌍으로 서명할 수 있다   
<br/>
## JWT와 관련된 표준
![900_JWS_JWE_Banner](https://user-images.githubusercontent.com/41939976/89265820-08c48700-d670-11ea-961d-80113bc990e6.png)

### JWS(Signature)   
- JSON데이터 구조를 사용하는 서명표준   
- JWS는 JSON으로 전자서명하여 URL-safe 문자열로 표현한 것이다   

### JWE(Encryption)   
- JSON데이터 구조를 사용하는 암호화 방법      
- JWE는 JSON으로 암호화하여 URL-safe 문자열로 표현한 것이다   

### URL-safe란?
- URL에 포함될 수 없는 문자를 포함하지 않는 것

### Signature란?
- 서명할때 사용한 키를 사용하여 JSON이 손상되지 않았는지 확인 하는 것

## JWT 토큰 구성
![json-web-token-overview1](https://user-images.githubusercontent.com/41939976/89266708-38c05a00-d671-11ea-812a-c0a3918a02df.png)
JWT는 크게 .으로 구분하여 3 파트로 나뉘어 진다 (Header,Payload,Signature)

JWT에서 토큰은 헤더와 Payload로 나눠짐  

Header: 암호화 알고리즘 및 Type을 의미함   
{   
  "alg":"HS256",//알고리즘   
  "typ":"JWT"//유형   
}   
   
Payload : 전송할 내용   
{   
  "test":0000001,//사용자고유번호   
  "User":"TestUser1",//사용자이름   
  "auth":"nomal_user"//관리자역할여부   
}   

Signature : 전송된 내용 확인   
<br/>
//헤더 영역과 데이터 영역을 결합한 데이터를 서버 비밀키(SecretKey)를 통해 HMAC알고리즘으로 암호화합니다.    
HMACSHA256(base64UrlEncode(header)+"."+base64UrlEncode(payload),KEY)   

#### URL과 URI의 차이
- URL > URI 구조
- URI : 인터넷 상의 자원을 식별하기 위한 문자열의 구성
- URL : 인터넷 상의 자원의 위치와 식별자 (파일의 위치 표시하기 위한)

Base64 인코딩 경우 +, -, /, = 이 포함되지만 JWT는 URI에서 파라미터로 사용할 수 있도록 URL-safe한 Base64url인코딩을 사용한다

### Header
- 토큰의 타입 + 해시암호화 알고리즘 구조
- 토큰의 타입 : 토큰의 유형(JWT)
- 해시암호화 알고리즘 : HMAC,SHA256 또는 RSA와 같은 해시 알고리즘

### Payload
- 토큰에 담을 속성정보(claim)를 포함하고 있다
- 이 payload에 담는 정보의 한 조각을 'claim'이라 부르고 이 클레임은 name/value 한쌍으로 이루어져 있다
- 토큰에는 여러개의 클레임들을 넣을 수 있다
- 클레임의 정보는 Registered(등록된), Public(공개), Private(비공개) 클레임으로 세 종류가 있다

### Signature
- secretkey를 포함하여 암호화 되어있다

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
![jwt_process_image_v2](https://user-images.githubusercontent.com/41939976/89481815-881e9b80-d7d3-11ea-852f-45870d3fef81.png)
1. 사용자가 id와 password를 입력하여 로그인을 시도합니다   
2. 서버는 요청을 확인하고 secret key를 통해 Access token을 발급합니다   
3. JWT 토큰을 클라이언트에 전달 합니다   
4. 클라이언트에서 API 을 요청할때  클라이언트가 Authorization header에 Access token을 담아서 보냅니다   
5. 서버는 JWT Signature를 체크하고 Payload로부터 사용자 정보를 확인해 데이터를 반환합니다   
6. 클라이언트의 로그인 정보를 서버 메모리에 저장하지 않기 때문에 토큰기반 인증 메커니즘을 제공합니다   
인증이 필요한 경로에 접근할 때 서버 측은 Authorization 헤더에 유효한 JWT 또는 존재하는지 확인한다   
JWT에는 필요한 모든 정보를 토큰에 포함하기 때문에 데이터베이스과 같은 서버와의 커뮤니케이션 오버 헤드를 최소화 할 수 있습니다   
Cross-Origin Resource Sharing (CORS)는 쿠키를 사용하지 않기 때문에 JWT를 채용 한 인증 메커니즘은 두 도메인에서 API를 제공하더라도 문제가 발생하지 않습니다   
일반적으로 JWT 토큰 기반의 인증 시스템은 위와 같은 프로세스로 이루어집니다   
처음 사용자를 등록할 때 Access token과 Refresh token이 모두 발급되어야 합니다   

## 인증 방식 비교하기 (Session-Cookie VS Token)
확장성을 고려한다면 Token 인증     
두 방식의 차이점을 확장성 측면에서 살펴보겠습니다   
### Session-Cookie 인증   
![sessionCookie1](https://user-images.githubusercontent.com/41939976/89484266-1cd7c800-d7d9-11ea-8988-4d1ede6905f9.png)
- 확장성 👎   
- Stateful : 모든 사용자의 인증상태(Session)를 유지하고 있어야 함   
- Traffic 고려 O: 사용자가 많아지면 Session 저장소가 Traffic을 감당해야 함 (조회, 등록)   
- 공유 자원 O : Server 증설시 Session 저장소를 공유해야 함   

### Token 인증
![0_2sni0qf84rLK70SD](https://user-images.githubusercontent.com/41939976/89490823-b8bd0000-d7e8-11ea-8a3d-bfa0c9bc5848.png)
- 확장성 👍     
- Stateless : Session 저장소 처럼 사용자의 인증 상태 데이터를 별도 저장소로 유지할 필요가 없음   
- Traffic 고려 X, 공유 자원 X : 각 Server가 토큰 발급만 잘 해주면 됨   

## 마이크로서비스라면 무조건 JWT!
### JWT의 핵심
마이크로서비스에서 JWT로 인증하면 불필요한 인증 과정을 줄여줍니다   
자세한 내용은 아래의 두 가지 토큰을 비교하며 살펴보겠습니다   

A. Payload가 없는 Token (Opaque Token) 👎   
B. Payload가 있는 Token (JWT) 👍   

### A. Payload가 없는 Token (Opaque Token)
아래 그림은 보통 Oauth2.0하면 생각하는 구조입니다   
![1](https://user-images.githubusercontent.com/41939976/89491104-6d572180-d7e9-11ea-974e-c7f63f84a939.png)
Resource 서버가 많아지면 Auth 서버가 너무 바빠집니다   
각각의 Resource 서버가 Token의 유효성, 권한 확인을 Auth 서버에 요청하기 때문입니다(이미 인증했는데…. 낭비…)   
![2](https://user-images.githubusercontent.com/41939976/89491170-95468500-d7e9-11ea-9d44-80ff19c48bb2.png)
바쁜 Auth 서버..   
그래서 Resource 서버가 많은 마이크로서비스에서는 Token만으로 유효성 & 권한 확인이 가능한 JWT가 필요합니다   

### B. Payload가 있는 Token (JWT)   
JWT를 사용하면 Auth 서버에 매번 요청할 필요가 없습니다   
JWT에 모든 정보가 포함되어 있기 때문에, 개별 서비스들은 자체적으로 Token의 유효성, 권한 정보를 체크한 후 바로 Resource를 제공합니다    
![3](https://user-images.githubusercontent.com/41939976/89491266-d343a900-d7e9-11ea-88ab-e303744ce353.png)

## JWT 사용시 주의 할 점   
### 1. Local Storage에 저장하지 마세요! ❌   
정말 위험합니다! 아무리 데이터 암호화를 잘 해도 Token이 털리면 아무 의미가 없습니다   
Local Storage에 저장하면 웹 브라우저에 영구적으로 저장되고, 자바스크립트를 통해 접근 가능하기 때문에 보안(특히 XSS 공격)에 취약합니다!   
최소한 메모리에 저장해두세요. (ex. Vue.js로 SPA를 개발했다면 Vuex 사용)   
### 2. JWT와 Session-Cookie를 모두 사용하기   
![4](https://user-images.githubusercontent.com/41939976/89491429-3f261180-d7ea-11ea-9aee-43e2cbafe370.png)
사용자의 서비스 경험을 방해하지 않고 인증을 다시 하는 방식입니다   
재인증을 위해 다시 로그인 창을 띄우지 않고, Hidden iframe에서 인증 시 필요한 Redirect 처리까지 진행합니다   
추가 팁! Access Token이 만료되어 다시 인증해서 JWT를 발급받아야 할 때는 Cookie에 로그인 Session 정보를 담아두어서 사용해야 합니다   
(보통 SPA에는 Refresh Token을 제공하지 않습니다. Refresh Token이 있으면 Access Token을 영원히 갱신할 수 있기 때문입니다)  

- 이유   
1.Local Storage에 JWT를 저장하지 않으면 사용자가 브라우저를 껐다 켤 때 마다 로그인을 다시 해야 합니다   
2.하지만 로그인에 Cookie를 사용하면 사용자를 방해하지 않고도 (UX 중단 없이, 재-로그인 없이) JWT를 재발급받을 수 있습니다   
3.게다가 Cookie는 자바스크립트에서 접근을 못하도록 보안 설정이 가능합니다  
   
### 3. 로그아웃 🔓   
간단하게 저장해둔 JWT를 삭제하면 됩니다. 이제 Client가 서버에 로그아웃을 요청할 필요가 없습니다!   
+ 서버에서 블랙리스트를 관리하여 JWT를 만료시키는 방법도 있습니다.   

## JWT 의 보안적 문제들
### 1. 토큰 내 중요한 정보 노출
일단 가장 흔한 경우는 이 토큰을 만들기 위해 사용되는 데이터들입니다   
토큰이기 때문에 각 계정이나 세션을 의미하는 고유한 데이터도 포함될 수 있고 개인정보도 포함될수도 있습니다   
보안 분석가라면 이 부분은 꼭 체크해주시고, 개발자라면 중요한 정보는 사용되지 않도록 구성해야 할 것입니다   
   
### 2. 토큰 내 값 조작으로 인가되지 않은 접근 권한 획득(Signature에 대한 해법이 필요)
이 방법은 토큰 내 권한이나 인가에 관련된 값을 변조하여 공격을 수행할 수 있습니다   
단순하게 토큰에 의존하여 사용자를 식별한다면 공격자는 토큰을 위조하여 서버를 속일수도 있죠   

아래 샘플은 jwt 공식 홈(https://jwt.io/) 에서 제공되는 기본 sample 코드입니다   
여기서 보아도 payload 데이터에 admin을 의미하는 값이 들어있습니다   
![선택 영역_015](https://user-images.githubusercontent.com/41939976/89480633-d0888a00-d7d0-11ea-823b-9ab3655193ef.png)   
   
## JWT 취약점에 따른 보안법
사용자의 상태를 유지하지 않는 stateless한 서비스를 운영할 때는 보안 이슈가 문제가 됩니다. 이를 해결하기 위한 보안 솔루션 중 하나가 JSON Web Token입니다.   
이를 이용해서 보안 정책을 세우는 경우 토큰 관리에 여러 전략을 이용 할 수 있습니다.   
JWT가 제공하는 기본적인 AccessToken 외에 RefreshToken을 도입한다거나 Sliding Sessions 전략을 활용할 수 있는데 이에 따라 그 장/단점이 달라집니다.   
알고리즘 때문에 위변조가 불가능하다고 하는데 불가능 하지 않습니다(https://code-machina.github.io/2019/09/01/Security-On-JSON-Web-Token.html)

----------------
### AccessToken 사용
사용자가 로그인을 할 때 클라이언트에게 AccessToken을 발급합니다. 서버는 AccessToken을 데이터베이스나 파일등에 저장 할 필요 없이 메모리상에서 미리 정의 된 비밀키를 이용해 비교하는 것 만으로 인증을 처리하기 때문에 추가적인 I/O 작업이 필요가 없습니다. 반면에 그런 이유로 서버는 특정 사용자의 접속을 강제로 만료시키기 어렵습니다. 일반적으로 클라이언트는 스스로의 저장 공간에서 토큰을 삭제하는 방법을 사용해 사용자의 접근을 막습니다.   

----------------
#### 1. 짧은 만료 시간을 설정   
JWT는 토큰의 만료 시간을 설정 할 수 있는데, 이를 30분 내의 짧은 기간으로 설정하는 경우에 대한 장/단점을 알아보겠습니다.   

- 장점   
기기나 AccessToken이 탈취되더라도 빠르게 만료됩니다.   
- 단점   
사용자는 자주 로그인을 해야 합니다. 한 사용자가 오랫동안 상주하는 서비스라면 서비스를 이용하는 도중에 갑자기 인증이 만료되어 로그인창이 뜨는 경우를 볼 수 있습니다.   
----------------
#### 2. 긴 만료 시간을 설정   
짧은 만료 시간을 설정했을 때의 단점을 상쇄하기 위해 2주에서 한달 정도로 만료 시간을 길게 주면 어떨까요? 당연하게도 위에서 살펴본 장, 단점과 정반대의 상황이 벌어집니다.      

- 장점   
사용자가 로그인을 자주 할 필요가 없습니다.   
- 단점   
기기나 AccessToken이 탈취되면 오랫동안 제약 없이 사용이 가능합니다.     
----------------
### Sliding Sessions 전략과 함께 AccessToken 사용   
보안성과 편의성 모두를 잡을 수는 없을까를 고민하다가 나온 것이 Sliding Sessions 전략입니다. 이 전략은 세션을 지속적으로 이용하는 유저에게 자동으로 만료 기한을 늘려주는 방법입니다.     
구현 방법은 다양합니다만 주로 유효한 AccessToken을 가진 클라이언트의 요청에 대해 서버가 새로운 AccessToken을 발급해주는 방법을 사용합니다. 매 요청마다 새로운 토큰을 내려주는 것도 가능하지만, 글을 작성하다가 인증이 만료되는 참담한 경우를 막기 위해 글 작성을 시작할 때 발급해준다거나, 쇼핑몰에서 장바구니에 아이템을 담는 경우에 발급해주는 등의 전략을 사용하는 것도 괜찮은 방법입니다. 또 클라이언트가 토큰의 iat(토큰 발급 시간)속성을 참조해서 갱신 요청을 하는 방법도 있습니다.   
이 방법을 활용하면 AccessToken만을 이용해 인증을 처리할 때 있었던 단점을 보완해 줄 수 있습니다.   

- 장점   
사용자가 로그인을 자주 할 필요가 없습니다.    
글을 작성하거나 결제를 하는 등의 세션 유지가 필요한 순간에 세션이 만료되는 문제를 방지 할 수 있습니다.   
- 단점   
접속이 주로 단발성으로 이루어지는 서비스의 경우 Sliding Sessions 전략의 효과가 크지 않습니다.   
긴 만료 시간을 갖는 AccessToken을 사용하는 경우 로그인을 전혀 하지 않아도 되는 경우가 발생합니다.   

----------------
### AccessToken과 RefreshToken을 사용   
사용자가 로그인을 할 때에 AccessToken과 함께 그에 비해 긴 만료 시간을 갖는 RefreshToken을 클라이언트에 함께 발급합니다. 주로 AccessToken은 30분 내외, RefreshToken은 2주에서 한달 정도의 만료 기간을 부여합니다.   
클라이언트는 AccessToken이 만료되었다는 오류를 받으면 따로 저장해두었던 RefreshToken을 이용하여 AccessToken의 재발급을 요청합니다. 서버는 유효한 RefreshToken으로 요청이 들어오면 새로운 AccessToken을 발급하고, 만료된 RefreshToken으로 요청이 들어오면 오류를 반환해, 사용자에게 로그인을 요구합니다.   
AccessToken은 서버에 따로 저장해 둘 필요가 없지만, RefreshToken의 경우 서버의 stroage에 따로 저장해서 이후 검증에 활용해야 합니다. 그러므로 RefreshToken을 이용한다는 것은 추가적인 I/O 작업이 필요하다는 의미이며, 이는 I/O 작업이 필요없는 빠른 인증 처리를 장점으로 내세우는 JWT의 스펙에 포함되지 않는 부가적인 기술입니다.   
RefreshToken은 탈취되어서는 곤란하므로 클라이언트는 보안이 유지되는 공간에 이를 저장해두어야 합니다.   
RefreshToken은 서버에서 따로 저장을 하고 있기 때문에 강제로 토큰을 만료시키는 것이 가능합니다.   

- 장점   
짧은 만료 기간을 사용 할 수 있기 때문에 AccessToken이 탈취되더라도 제한된 기간만 접근이 가능합니다.   
사용자가 로그인을 자주 할 필요가 없습니다.   
RefreshToken에 대한 만료를 강제로 설정 할 수 있습니다.   

- 단점   
클라이언트는 AccessToken의 만료에 대한 연장 요청을 구현해야 합니다.   
인증 만료 기간의 자동 연장이 불가능합니다.   
서버에 별도의 storage를 만들어야 합니다.   
----------------
### Sliding Sessions 전략과 함께 AccessToken과 RefreshToken을 사용   
AccessToken의 Sliding Sessions 전략이 AccessToken 자체의 만료 기간을 늘려주었다면, 이 전략은 RefreshToken의 만료 기간을 늘려줍니다.   
RefreshToken의 만료 기간이 늘어나기 때문에 AccessToken + Sliding Sessions 전략처럼 빈번하게 만료 기간 연장을 해줄 필요가 없고, 사용자의 유휴 허용 기간을 RefreshToken 기간에 근접하게 늘려줍니다.   
반면 사용자가 접속을 뜸하게 하는 경우에도 RefreshToken의 만료 기간의 늘어나기 때문에, 핸드폰이 탈취되는 등의 경우에 지속적인 이용이 가능 할 수 있습니다. 이를 막는 방법으로 인증이 확실히 요구되는 경우 비밀번호를 한번 더 묻는다거나, 비밀번호 변경 등의 이벤트가 발생 할 때 강제로 RefreshToken을 만료시키는 처리를 해주는 것이 좋습니다.   

- 장점   
RefreshToken의 만료 기간에 대한 제약을 받지 않습니다.   
글을 작성하거나 결제를 하는 등의 세션 유지가 필요한 순간에 세션이 만료되는 문제를 방지 할 수 있습니다.  

- 단점   
서버에서 강제로 RefreshToken을 만료하지 않는 한 지속적으로 사용이 가능합니다.   
인증이 추가로 요구되는 경우에 대한 보안 강화가 필요합니다.    

----------------
### 결론
일반적인 웹 서비스처럼 cookie등을 이용해 세션 관리를 하는 방식을 사용할 수 없는 stateless한 REST API등은 토큰 방식의 보안을 이용 할 수 밖에 없습니다. stateless하기 때문에 매 요청에 대한 인증을 거쳐야 하는데, 이는 데이터베이스 등으로부터 토큰을 얻어오는 추가적인 I/O 작업이 불가피하고 이는 성능의 하락으로 이어집니다. 이를 해결해주기 위한 솔루션이 바로 JWT입니다.   
JWT는 이런 장점과 함께 위에서 살펴봤듯이 여러가지 문제점들이 존재합니다. 토큰의 탈취에 대한 취약성, 서버의 클라이언트 제어 불가, 빈번한 로그인 요청 등의 문제에 대한 해결 방법은 RefreshToken이나 Sliding Sessions 등의 전략을 도입하는 것입니다. 하지만 이러한 전략들 역시 추가적인 IO 작업을 위한 성능 감소나, 편의를 위해 보안이 취약해지는 상황등이 발생할 가능성이 있습니다.   
서비스가 결제가 필요한 보안에 민감한 컨텐츠를 다루고 있다면 비밀번호 한번 더 입력하는 것이 크게 문제가 되지 않습니다. 반면, 게시물에 글을 작성할때마다 비밀번호를 입력해야 한다면 사용자들은 매우 귀찮아 할 것입니다. 결국 모든 것을 얻을 수는 없습니다. 서비스마다 가진 고유한 특성을 고려해 보안 수준을 높일지, 사용자 편의성을 높일지를 결정해야 합니다.   

