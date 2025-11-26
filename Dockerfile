Dockerfile을 생성할 때, HTML 프로젝트의 경우에는 주로 정적 파일을 제공하는 웹 서버를 설정하게 됩니다. 가장 일반적인 선택은 Nginx 또는 Apache와 같은 경량 웹 서버입니다. 여기서는 Nginx를 사용한 Dockerfile 예제를 제공하겠습니다.

```dockerfile
# Nginx 이미지를 기반으로 합니다.
FROM nginx:alpine

# Nginx 설정 파일을 복사합니다.
COPY nginx.conf /etc/nginx/nginx.conf

# 프로젝트의 HTML 파일을 Nginx의 기본 경로로 복사합니다.
COPY . /usr/share/nginx/html

# 컨테이너가 실행될 때 Nginx가 시작되도록 설정합니다.
CMD ["nginx", "-g", "daemon off;"]
```

위 Dockerfile은 다음과 같은 작업을 수행합니다:

1. `nginx:alpine` 이미지를 기반으로 하여 경량의 Nginx 서버를 사용합니다.
2. `nginx.conf` 파일을 복사하여 Nginx의 설정을 사용자 정의할 수 있습니다. (필요에 따라 설정 파일을 수정하세요.)
3. 현재 디렉토리의 모든 파일(HTML, CSS, JS 등)을 Nginx의 기본 경로(`/usr/share/nginx/html`)로 복사합니다.
4. Nginx가 포그라운드에서 실행되도록 설정하여 Docker 컨테이너가 계속 실행되도록 합니다.

`nginx.conf` 파일은 기본 설정을 사용할 수도 있고, 필요에 따라 다음과 같이 간단하게 작성할 수 있습니다:

```nginx
events {}

http {
    server {
        listen 80;
        server_name localhost;

        location / {
            root /usr/share/nginx/html;
            index index.html;
        }
    }
}
```

이 설정은 기본적으로 80번 포트에서 HTTP 요청을 수신하고, `/usr/share/nginx/html` 디렉토리에서 정적 파일을 제공합니다. 필요에 따라 설정을 조정하세요. Dockerfile과 Nginx 설정 파일을 프로젝트 루트에 추가한 후, `docker build -t my-html-app .` 명령어로 이미지를 빌드하고, `docker run -p 8080:80 my-html-app` 명령어로 컨테이너를 실행하여 로컬에서 테스트할 수 있습니다.