# AuthN Middleware Example

The current example demonstrates how to create a simple HTTP server that authenticates requests with JWT tokens.

The complete code example is available in the [main.go](./main.go) file.

Configuration is stored in the [config.yml](./config.yml) file.

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
$ curl 127.0.0.1:8080
{"error":{"domain":"MyService","code":"bearerTokenMissing","message":"Authorization bearer token is missing."}}
```

### Trying to access the service with an invalid token

```shell
$ curl -H "Authorization: Bearer invalid-token" 127.0.0.1:8080
{"error":{"domain":"MyService","code":"authenticationFailed","message":"Authentication is failed."}}
```
Service logs:
```
{"level":"error","time":"2024-10-06T23:47:11.554193+03:00","msg":"authentication failed","pid":76054,"request_id":"","int_request_id":"","trace_id":"","error":"token is malformed: token contains an invalid number of segments"}
{"level":"error","time":"2024-10-06T23:47:11.554201+03:00","msg":"error in response","pid":76054,"request_id":"","int_request_id":"","trace_id":"","error_code":"authenticationFailed","error_message":"Authentication is failed."}
{"level":"info","time":"2024-10-06T23:47:11.554226+03:00","msg":"response completed in 0.000s","pid":76054,"request_id":"","int_request_id":"","trace_id":"","method":"GET","uri":"/","remote_addr":"127.0.0.1:61538","content_length":0,"user_agent"
:"curl/8.7.1","remote_addr_ip":"127.0.0.1","remote_addr_port":61538,"duration_ms":0,"duration":299,"status":401,"bytes_sent":100}
```

### Doing a successful request

```shell
$ curl -XPOST -u user:user-pwd 127.0.0.1:8081/idp/token
{"access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJ1c2VyIiwiZXhwIjoxNzI4MjUxMjc3LCJqdGkiOiI2MGIzZjQxYy0wZjA0LTQ4NzQtYjdmNi02MjVkZWJjZmE1ZTQifQ.j7i4_TOqGIOyQFfldmo_lOk7KgDCaq6lXi9xzOWbtrTZJGYMrlLFlgE7Hp8FRU0Npfe7G-N8KswXKevkarZTB80xSwuHwxFbJOMP0J8d0vP-ihGfMXg2WfIxfQD3x0OkynyMz1nTBtquJJ5Yvg5m7xJSKDKU1iCY-e78yJ-yfwT25fHbF3Z5QHvHv8ITsKiwKM3RTDwXxDz1ruMoR4JuhLK7IPmN0eh2P3ZMOpRo-lrXU8b0_UyMeoGMxcA4tSuOLdMLmqzfVTX4wDpcHJCaZROxfK9uZNWPeVOahMp2khg0-b6cDS-CPMIMVsta7LQHqzfvpXuAkB0iJFYLsCDs4A","expires_in":3600}

$ curl 127.0.0.1:8080 -H"Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJ1c2VyIiwiZXhwIjoxNzI4MjUxMjc3LCJqdGkiOiI2MGIzZjQxYy0wZjA0LTQ4NzQtYjdmNi02MjVkZWJjZmE1ZTQifQ.j7i4_TOqGIOyQFfldmo_lOk7KgDCaq6lXi9xzOWbtrTZJGYMrlLFlgE7Hp8FRU0Npfe7G-N8KswXKevkarZTB80xSwuHwxFbJOMP0J8d0vP-ihGfMXg2WfIxfQD3x0OkynyMz1nTBtquJJ5Yvg5m7xJSKDKU1iCY-e78yJ-yfwT25fHbF3Z5QHvHv8ITsKiwKM3RTDwXxDz1ruMoR4JuhLK7IPmN0eh2P3ZMOpRo-lrXU8b0_UyMeoGMxcA4tSuOLdMLmqzfVTX4wDpcHJCaZROxfK9uZNWPeVOahMp2khg0-b6cDS-CPMIMVsta7LQHqzfvpXuAkB0iJFYLsCDs4A"
Hello, user
```
Service logs:
```
{"level":"info","time":"2024-10-06T23:48:14.106249+03:00","msg":"2 keys fetched (jwks_url: http://127.0.0.1:8081/idp/keys)","pid":76054}
{"level":"info","time":"2024-10-06T23:48:14.10667+03:00","msg":"response completed in 0.002s","pid":76054,"request_id":"","int_request_id":"","trace_id":"","method":"GET","uri":"/","remote_addr":"127.0.0.1:61581","content_length":0,"user_agent":"curl/8.7.1","remote_addr_ip":"127.0.0.1","remote_addr_port":61581,"duration_ms":2,"duration":2116,"status":200,"bytes_sent":11}
```
