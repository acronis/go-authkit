# Token Introspection Example

The example below demonstrates how to create a simple HTTP server that authenticates requests with JWT tokens using the token introspection endpoint.
Additionally, it performs authorization based on the introspected token's scope.

## Usage

To be able to run this example, you need to have the IDP test server running (see [IDP Test Server Example](../idp-test-server/README.md) for more details).

```bash
go run ../idp-test-server/main.go
```

To start the server, run the following command:

```bash
go run main.go
```

The server will start on port 8080.

### Trying to access the service without a token

```shell
$ curl 127.0.0.1:8080
{"error":{"domain":"MyService","code":"bearerTokenMissing","message":"Authorization bearer token is missing."}}
```
Service logs:
```
{"level":"error","time":"2024-10-07T10:18:02.976885+03:00","msg":"error in response","pid":83030,"request_id":"","int_request_id":"","trace_id":"","error_code":"bearerTokenMissing","error_message":"Authorization bearer token is missing."}
{"level":"info","time":"2024-10-07T10:18:02.977616+03:00","msg":"response completed in 0.001s","pid":83030,"request_id":"","int_request_id":"","trace_id":"","method":"GET","uri":"/","remote_addr":"127.0.0.1:50735","content_length":0,"user_agent":"curl/8.7.1","remote_addr_ip":"127.0.0.1","remote_addr_port":50735,"duration_ms":0,"duration":798,"status":401,"bytes_sent":111}
```

### Doing requests with a user's token

```shell
$ curl -XPOST -u user:user-pwd 127.0.0.1:8081/idp/token
{"access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJ1c2VyIiwiZXhwIjoxNzI4Mjk0ODY5LCJqdGkiOiI0NzRhZTRiYS0wMDkyLTQwZmItOGY2MS02NGFjMWE5NTQwNjgifQ.mIDx9XuqRZmaWtshrSMGuzC2ONQDOqliwuiCctQVCS_a_U19mbs2pbSNJXVd8TmPb2abP7ANgaF9htyuJohdyaIcgFU92dK_ParunHH-qihkMwfTyUMMoQu4YQWSZhc8MBY5xQBb1LchV2uYxc1m402E1nvuXZY4FGbYxy8tdaTMMTJWBjStouMZ0meSDvwSP2mu7J8pCD4V3J6Um4gxtfaesovdyXahdlCwh34e0ey2_KcIuGR3QCOJYNRyEG2CYuMe5mfSrC5f0PkLpBY3G94pSJ_naf0qg4Xz-qmezA1KmAIqWUWXI1jS9UFTwuM4A7M0vPHbU3TXBcIW_yXoQw","expires_in":3600}

$ curl -XPOST -H"Authorization: Bearer access-token-with-introspection-permission" 127.0.0.1:8081/idp/introspect_token -d token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJ1c2VyIiwiZXhwIjoxNzI4Mjk0ODY5LCJqdGkiOiI0NzRhZTRiYS0wMDkyLTQwZmItOGY2MS02NGFjMWE5NTQwNjgifQ.mIDx9XuqRZmaWtshrSMGuzC2ONQDOqliwuiCctQVCS_a_U19mbs2pbSNJXVd8TmPb2abP7ANgaF9htyuJohdyaIcgFU92dK_ParunHH-qihkMwfTyUMMoQu4YQWSZhc8MBY5xQBb1LchV2uYxc1m402E1nvuXZY4FGbYxy8tdaTMMTJWBjStouMZ0meSDvwSP2mu7J8pCD4V3J6Um4gxtfaesovdyXahdlCwh34e0ey2_KcIuGR3QCOJYNRyEG2CYuMe5mfSrC5f0PkLpBY3G94pSJ_naf0qg4Xz-qmezA1KmAIqWUWXI1jS9UFTwuM4A7M0vPHbU3TXBcIW_yXoQw
{"active":true,"iss":"http://127.0.0.1:8081","sub":"user","exp":1728294869,"jti":"474ae4ba-0092-40fb-8f61-64ac1a954068"}

$ curl 127.0.0.1:8080 -H"Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJ1c2VyIiwiZXhwIjoxNzI4Mjk0ODY5LCJqdGkiOiI0NzRhZTRiYS0wMDkyLTQwZmItOGY2MS02NGFjMWE5NTQwNjgifQ.mIDx9XuqRZmaWtshrSMGuzC2ONQDOqliwuiCctQVCS_a_U19mbs2pbSNJXVd8TmPb2abP7ANgaF9htyuJohdyaIcgFU92dK_ParunHH-qihkMwfTyUMMoQu4YQWSZhc8MBY5xQBb1LchV2uYxc1m402E1nvuXZY4FGbYxy8tdaTMMTJWBjStouMZ0meSDvwSP2mu7J8pCD4V3J6Um4gxtfaesovdyXahdlCwh34e0ey2_KcIuGR3QCOJYNRyEG2CYuMe5mfSrC5f0PkLpBY3G94pSJ_naf0qg4Xz-qmezA1KmAIqWUWXI1jS9UFTwuM4A7M0vPHbU3TXBcIW_yXoQw"
Hello, user

$ curl 127.0.0.1:8080/admin -H"Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJ1c2VyIiwiZXhwIjoxNzI4Mjk0ODY5LCJqdGkiOiI0NzRhZTRiYS0wMDkyLTQwZmItOGY2MS02NGFjMWE5NTQwNjgifQ.mIDx9XuqRZmaWtshrSMGuzC2ONQDOqliwuiCctQVCS_a_U19mbs2pbSNJXVd8TmPb2abP7ANgaF9htyuJohdyaIcgFU92dK_ParunHH-qihkMwfTyUMMoQu4YQWSZhc8MBY5xQBb1LchV2uYxc1m402E1nvuXZY4FGbYxy8tdaTMMTJWBjStouMZ0meSDvwSP2mu7J8pCD4V3J6Um4gxtfaesovdyXahdlCwh34e0ey2_KcIuGR3QCOJYNRyEG2CYuMe5mfSrC5f0PkLpBY3G94pSJ_naf0qg4Xz-qmezA1KmAIqWUWXI1jS9UFTwuM4A7M0vPHbU3TXBcIW_yXoQw"
{"error":{"domain":"MyService","code":"authorizationFailed","message":"Authorization is failed."}}
```
Service logs:
```
{"level":"info","time":"2024-10-07T10:23:23.862735+03:00","msg":"response completed in 0.005s","pid":83030,"request_id":"","int_request_id":"","trace_id":"","method":"GET","uri":"/","remote_addr":"127.0.0.1:50886","content_length":0,"user_agent":"curl/8.7.1","remote_addr_ip":"127.0.0.1","remote_addr_port":50886,"duration_ms":4,"duration":4688,"status":200,"bytes_sent":11}

{"level":"error","time":"2024-10-07T10:46:21.621356+03:00","msg":"error in response","pid":83410,"request_id":"","int_request_id":"","trace_id":"","error_code":"authorizationFailed","error_message":"Authorization is failed."}
{"level":"info","time":"2024-10-07T10:46:21.621421+03:00","msg":"response completed in 0.002s","pid":83410,"request_id":"","int_request_id":"","trace_id":"","method":"GET","uri":"/admin","remote_addr":"127.0.0.1:51469","content_length":0,"user_a
gent":"curl/8.7.1","remote_addr_ip":"127.0.0.1","remote_addr_port":51469,"duration_ms":1,"duration":1673,"status":403,"bytes_sent":98}
```

### Doing requests with an admin2's token

admin2's token has no access policies in the scope, but after introspection, the service will allow access to the /admin endpoint.

```shell
$ curl -XPOST -u admin2:admin2-pwd 127.0.0.1:8081/idp/token
{"access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJhZG1pbjIiLCJleHAiOjE3MjgyOTQ3MjksImp0aSI6ImZkY2QyMzRiLWJmMGEtNDgxNC1hNTIzLTg2MjZlNmI0MDA2YyJ9.ZCkklH8UtCnL6KLV1L1wimNEKJqCBPErzslNBu_Ox9Cahg590nl1TwdnOrIQgjvPTgRzk5hpiFEiXIsCY1uxtxTiWKtRqGPnKRnityvnQ7VMEc7Iwj-pKstoSr5qGBFbzWrn-4U-yD6xCXvj7DsKyTx-zYVGfbhRQXj8lDRIkfv9fTDfl3htZMKuwMi-fVavaOEJ4ZRGVIQSVd0ku_lXwB28hHP90n5MNmZPqAzcI-j-ribVcrfySe6bN8_7n4hmsk8YNFAPQaXsE5WA868LOKJTsVB4IZifIa7d107okjk8JTFuh-Vktkm8KW6H_TX6-UEWlM1kQKPqoXC5KlLecQ","expires_in":3600}

$ curl -XPOST -H"Authorization: Bearer access-token-with-introspection-permission" 127.0.0.1:8081/idp/introspect_token -d token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJhZG1pbjIiLCJleHAiOjE3MjgyOTQ3MjksImp0aSI6ImZkY2QyMzRiLWJmMGEtNDgxNC1hNTIzLTg2MjZlNmI0MDA2YyJ9.ZCkklH8UtCnL6KLV1L1wimNEKJqCBPErzslNBu_Ox9Cahg590nl1TwdnOrIQgjvPTgRzk5hpiFEiXIsCY1uxtxTiWKtRqGPnKRnityvnQ7VMEc7Iwj-pKstoSr5qGBFbzWrn-4U-yD6xCXvj7DsKyTx-zYVGfbhRQXj8lDRIkfv9fTDfl3htZMKuwMi-fVavaOEJ4ZRGVIQSVd0ku_lXwB28hHP90n5MNmZPqAzcI-j-ribVcrfySe6bN8_7n4hmsk8YNFAPQaXsE5WA868LOKJTsVB4IZifIa7d107okjk8JTFuh-Vktkm8KW6H_TX6-UEWlM1kQKPqoXC5KlLecQ
{"active":true,"iss":"http://127.0.0.1:8081","sub":"admin2","exp":1728294729,"jti":"fdcd234b-bf0a-4814-a523-8626e6b4006c","scope":[{"rn":"my_service","role":"admin"}]}

$ curl 127.0.0.1:8080/admin -H"Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJhZG1pbjIiLCJleHAiOjE3MjgyOTQ3MjksImp0aSI6ImZkY2QyMzRiLWJmMGEtNDgxNC1hNTIzLTg2MjZlNmI0MDA2YyJ9.ZCkklH8UtCnL6KLV1L1wimNEKJqCBPErzslNBu_Ox9Cahg590nl1TwdnOrIQgjvPTgRzk5hpiFEiXIsCY1uxtxTiWKtRqGPnKRnityvnQ7VMEc7Iwj-pKstoSr5qGBFbzWrn-4U-yD6xCXvj7DsKyTx-zYVGfbhRQXj8lDRIkfv9fTDfl3htZMKuwMi-fVavaOEJ4ZRGVIQSVd0ku_lXwB28hHP90n5MNmZPqAzcI-j-ribVcrfySe6bN8_7n4hmsk8YNFAPQaXsE5WA868LOKJTsVB4IZifIa7d107okjk8JTFuh-Vktkm8KW6H_TX6-UEWlM1kQKPqoXC5KlLecQ"
Hi, admin2
```
Service logs:
```
{"level":"info","time":"2024-10-07T10:48:24.885616+03:00","msg":"response completed in 0.003s","pid":84516,"request_id":"","int_request_id":"","trace_id":"","method":"GET","uri":"/admin","remote_addr":"127.0.0.1:51527","content_length":0,"user_agent":"curl/8.7.1","remote_addr_ip":"127.0.0.1","remote_addr_port":51527,"duration_ms":2,"duration":2866,"status":200,"bytes_sent":10}
```

## Static HTTP and gRPC introspection endpoint configuration

By default, the introspection endpoint is obtained from the OpenID Connect Discovery response. The library will use the endpoint specified in the `introspection_endpoint` field in the <issuer_url>/.well-known/openid-configuration response body.
But it can be configured statically as well. It could be useful in multiple cases:
- When the introspection endpoint is not supported by the IDP.
- Not JWT token is used for authentication (e.g., opaque token).
- When we want to have a single point of introspection for all tokens.
- When performance is critical, and we want to use persistent gRPC connection.

To configure the static introspection endpoint, add the following configuration to the `config.yaml` file:

```yaml
auth:
  introspection:
    endpoint: <static_http_url>
```

Additionally, the introspection can be configured to use gRPC instead of HTTP for the introspection request.
If `grps.tls.enabled` is set to `true`, the introspection request will be made over a secure connection.
If `grps.tls.client_cert` and `grps.tls.client_key` are set, the introspection request will be made with client authentication (mutual TLS).

```yaml
auth:
  introspection:
    grpc:
      target: <static_grpc_url>
      tls:
        enabled: true
        caCert: <path_to_ca_cert>
        clientCert: <path_to_client_cert>
        clientKey: <path_to_client_key>
```

If you want to test introspection via gRPC, you can use the [gRPC introspection server example](./grpc-server).
To start the gRPC introspection server, just run `go run ./grpc-server/main.go`.

Then modify the `config.yaml` file to use the gRPC introspection endpoint:

```yaml
auth:
  introspection:
    grpc:
      endpoint: 127.0.0.1:50051
```

Now, the introspection request will be made to the gRPC server.

Static endpoint configuration has higher priority than the dynamic one.