# oauth2proxy-sample-for-developper
A simple oauth2-proxy sample project using keycloak and python moc application

## Run application

### 1. deploy oauth2-proxy

Get oauth2-proxy binary file from [git repository](https://github.com/oauth2-proxy/oauth2-proxy/releases) or by building yourself. And put it in the [oauth2proxy/src/](oauth2proxy/src/) folder. 

### 2. write hosts entry

Write the following entry in `hosts` file.

```
127.0.0.1 oauth2proxy.localhost.com
127.0.0.1 keycloak.localhost.com
127.0.0.1 pymocserver.localhost.com
```

### 3. start containers

Containers can be started, stopped or restarted using `docker-compose` command

To start containers

```
docker-compose up
```

To delete containers

```
docker-compose down
```

To restart a particular container

```
docker-compsoe restart oauth2proxy
```

### 4. access moc application

Endpoints are described at [endpoints](https://oauth2-proxy.github.io/oauth2-proxy/docs/features/endpoints).  
Sign in endpoint is [http://oauth2proxy.localhost.com:4180/oauth2/sign_in](http://oauth2proxy.localhost.com:4180/oauth2/sign_in) for this application.   

| URL                                   | Description        |
| ------------------------------------- | ------------------ |
| http://oauth2proxy.localhost.com:4180 | Oauth2Proxy server |
| http://keycloak.localhost.com:8080    | Keycloak console   |
| http://pymocserver.localhost.com:8000 | python moc server  |

Useres are created in the keycloak in advance.  
`admin` user is used to sign in the keycloak console and others are python moc server.  

| Realm           | Username | Password | Email             | First Name | Last Name | User Enabled | Email Verified |
| --------------- | -------- | -------- | ----------------- | ---------- | --------- | ------------ | -------------- |
| master          | admin    | password | admin@example.com | adminFirst | adminLast | true         | true           |
| dev_oauth2proxy | user1    | password | user1@example.com | u1First    | u1Last    | true         | true           |
| dev_oauth2proxy | user2    | password | user2@example.com | u2First    | u2Last    | true         | true           |
| dev_oauth2proxy | user3    | password | user3@example.com | u3First    | u3Last    | true         | true           |
| dev_oauth2proxy | user4    | password | user4@example.com | u4First    | u4Last    | false        | true           |
| dev_oauth2proxy | user5    | password | user5@example.com | u5First    | u5Last    | true         | false          |
| dev_oauth2proxy | user6    | password | user6@example.com | u6First    | u6Last    | false        | false          |

## Client info

oauth2-proxy is configured in the keycloak as  

- Client ID      : `oauth2proxy`  
- Client Secret  : `r4jwmwLU4GEsf53TnGkqJWfNtAdwWhqU`  
- well-known URL : http://keycloak.localhost.com:8080/auth/realms/dev_oauth2proxy/.well-known/openid-configuration

## Build oauth2-proxy from source code

**go command**

```
go build
```

**Makefile**

Building oauth2-proxy using a Makefile requires installation of  gcc, make in addition of golang.  
Here shows how to build oauth2-proxy using docker container.  
Source codes shoud be in the [oauth2proxy/src/](oauth2proxy/src/) folder.  

```
docker run -it --rm -v ${PWD}/oauth2proxy/src:/go/src golang:1.18.0 bash -c "cd /go/src && make build"
```

## Export keycloak settings

Keycloak configurations can be exported with the following command.  
Running the command overwrite existing configuration in [keycloak/realm-config/](keycloak/realm-config/).  

```
docker exec -it keycloak /opt/jboss/keycloak/bin/standalone.sh -Djboss.socket.binding.port-offset=1000 -Dkeycloak.migration.action=export -Dkeycloak.migration.provider=dir -Dkeycloak.migration.dir=/opt/keycloak/realm-config
```

## References

- https://github.com/oauth2-proxy/oauth2-proxy
- https://www.dumels.com/diagram/3c1550f5-3736-43da-824e-42a75a0194a3