# IDP Test Server Example

This is a [simple test server](./main.go) that can be used to test the IDP client.
It demonstrates how the `idptest` package can be used to create a simple IDP server.

## Usage

To start the server, run the following command:

```bash
go run main.go
```

The server will start on port 8081.

Getting well-known configuration:
```bash
$ curl 127.0.0.1:8081/.well-known/openid-configuration
{"token_endpoint":"http://127.0.0.1:8081/idp/token","introspection_endpoint":"http://127.0.0.1:8081/idp/introspect_token","jwks_uri":"http://127.0.0.1:8081/idp/keys"}
```

Issuing JWT tokens:
```bash
$ curl -XPOST -u user:user-pwd 127.0.0.1:8081/idp/token
{"access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJ1c2VyIiwiZXhwIjoxNzI4MjUwMTIzLCJqdGkiOiI0NGFkOTMxNy0xNTNiLTRjYjUtYmQ3ZC0wMWJiOGRjOGJlZjAifQ.N-2p4qIBHsVMrsvHoxdTgeYa72oNQRa4vVXzsV9c9Km_sPhFKPaVIqthKxDHvoh_DUCpuVRBFOXc7thXL3vB2fMBU9YQOarC6Mfd8Q28vUQ_C05PJl2DsM29Y3LEXBpXAzjIKdcCkMnGvSf74gaVkbD5ehzxmpMWJ8k2xoLVLZOyUxncColiPYD6Srs_etmF1ODJ9quuen_ZwxH0tpjJ6pv7rFWMdjrFbmjQj-JgzWRL-aiuvcdiGccjJ8YlmnwGZNWNYXZaoug7p0Hci-yB6TmB_f36_1sydAOp8wiiSZ7ECjPjKc2gzLaazvbxCqY0pXBtXWT06a83tpF7PDg1jg","expires_in":3600}

$ curl -XPOST -u admin:admin-pwd 127.0.0.1:8081/idp/token # token's scope for admin will be [{"rn": "my_service","role": "admin"}]
{"access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJhZG1pbiIsImV4cCI6MTcyODI1MDE0NSwianRpIjoiMmUxNTM1YmMtNTlmNC00YWU2LTg5ZTEtMmRjNTQyY2U3NTlhIiwic2NvcGUiOlt7InJuIjoibXlfc2VydmljZSIsInJvbGUiOiJhZG1pbiJ9XX0.JyEcmgoThSYTHTRcFeNStwdAqN7W2pqeO456VTsEI7zWX0EDHr4-HIj4iLDoIyGQzsSMoUcnSEon2thKki6DUkXqc9Kg4iNYgUVVRp6lK5oBqFYGOBj8rlsInEZ03OuoSBhmfdD07EgoHySOXTrZqxFrBJ_mnzvLfA0wXVtwUgKCQBRWQIyAWg-HQotSs7qU_pmmSDgToRlBN5m-j1rkmPay4g5yOjiuRj5l9IxmjxDt_RuOK1-aId2NOT4Jomf4vijSwAG69owgzuPtLqLaFVYQ-bplpZ5EFaPF7f99KuZN2HphhMhuPEx6xuNxKafXQo1NXENjoDvAzHc3TcvcOw","expires_in":3600}

$ curl -XPOST -u admin2:admin2-pwd 127.0.0.1:8081/idp/token # token's scope for admin2 will be empty
{"access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJhZG1pbjIiLCJleHAiOjE3MjgyODk4OTQsImp0aSI6IjJiZDc3ZjJhLTBlYTUtNGJmYi04NDU1LWMwZWZjNDM3MDdmNyJ9.Yk4Z6fkiLCGIsAz7qRX1twwLuHt7lXB7KRvpshnPg87b6lnkEhZry7x9aCW6PSjSHvWiGiGhKBRYfhqtHw0umJFf5GtNprRJLj6kMj9Z2HFLirCpjeyMECszcDo-NAqjt-8BcZEis_aCoxXTe_NWE1KjncflhWUMX5XOE4VS8aZn2y2OgGUW1E1qO3uX3H69bt03BB0ZYTPdltKngJcV2HzJuZ9017qKMd3uDBE5W1wVyOleM8Yr-7IaUztQOxyjKbPdsBU8n1F64zm1-RzEriYSq1G6oJfqEkDNc1q0oThM_zN72056vLi5xWUHRbsN7CzZ5WeGQ5vcpUE3PqRquw","expires_in":3600}
```

Introspecting JWT tokens:
```bash
# introspecting user's token
$ curl -XPOST -H"Authorization: Bearer access-token-with-introspection-permission" 127.0.0.1:8081/idp/introspect_token -d token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJ1c2VyIiwiZXhwIjoxNzI4MjUwMTIzLCJqdGkiOiI0NGFkOTMxNy0xNTNiLTRjYjUtYmQ3ZC0wMWJiOGRjOGJlZjAifQ.N-2p4qIBHsVMrsvHoxdTgeYa72oNQRa4vVXzsV9c9Km_sPhFKPaVIqthKxDHvoh_DUCpuVRBFOXc7thXL3vB2fMBU9YQOarC6Mfd8Q28vUQ_C05PJl2DsM29Y3LEXBpXAzjIKdcCkMnGvSf74gaVkbD5ehzxmpMWJ8k2xoLVLZOyUxncColiPYD6Srs_etmF1ODJ9quuen_ZwxH0tpjJ6pv7rFWMdjrFbmjQj-JgzWRL-aiuvcdiGccjJ8YlmnwGZNWNYXZaoug7p0Hci-yB6TmB_f36_1sydAOp8wiiSZ7ECjPjKc2gzLaazvbxCqY0pXBtXWT06a83tpF7PDg1jg
{"active":true,"iss":"http://127.0.0.1:8081","sub":"user","exp":1728250123,"jti":"44ad9317-153b-4cb5-bd7d-01bb8dc8bef0"}

# introspecting admin's token
$ curl -XPOST -H"Authorization: Bearer access-token-with-introspection-permission" 127.0.0.1:8081/idp/introspect_token -d token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJhZG1pbiIsImV4cCI6MTcyODI1MDE0NSwianRpIjoiMmUxNTM1YmMtNTlmNC00YWU2LTg5ZTEtMmRjNTQyY2U3NTlhIiwic2NvcGUiOlt7InJuIjoibXlfc2VydmljZSIsInJvbGUiOiJhZG1pbiJ9XX0.JyEcmgoThSYTHTRcFeNStwdAqN7W2pqeO456VTsEI7zWX0EDHr4-HIj4iLDoIyGQzsSMoUcnSEon2thKki6DUkXqc9Kg4iNYgUVVRp6lK5oBqFYGOBj8rlsInEZ03OuoSBhmfdD07EgoHySOXTrZqxFrBJ_mnzvLfA0wXVtwUgKCQBRWQIyAWg-HQotSs7qU_pmmSDgToRlBN5m-j1rkmPay4g5yOjiuRj5l9IxmjxDt_RuOK1-aId2NOT4Jomf4vijSwAG69owgzuPtLqLaFVYQ-bplpZ5EFaPF7f99KuZN2HphhMhuPEx6xuNxKafXQo1NXENjoDvAzHc3TcvcOw
{"active":true,"iss":"http://127.0.0.1:8081","sub":"admin","exp":1728250145,"jti":"2e1535bc-59f4-4ae6-89e1-2dc542ce759a","scope":[{"rn":"my_service","role":"admin"}]}

# introspecting admin2's token
$ curl -XPOST -H"Authorization: Bearer access-token-with-introspection-permission" 127.0.0.1:8081/idp/introspect_token -d token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhYzAxYzA3MGNkMDhiYTA4ODA5NzYyZGE2ZTRmNzRhZjE0ZTQ3OTAiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEiLCJzdWIiOiJhZG1pbjIiLCJleHAiOjE3MjgyODk4OTQsImp0aSI6IjJiZDc3ZjJhLTBlYTUtNGJmYi04NDU1LWMwZWZjNDM3MDdmNyJ9.Yk4Z6fkiLCGIsAz7qRX1twwLuHt7lXB7KRvpshnPg87b6lnkEhZry7x9aCW6PSjSHvWiGiGhKBRYfhqtHw0umJFf5GtNprRJLj6kMj9Z2HFLirCpjeyMECszcDo-NAqjt-8BcZEis_aCoxXTe_NWE1KjncflhWUMX5XOE4VS8aZn2y2OgGUW1E1qO3uX3H69bt03BB0ZYTPdltKngJcV2HzJuZ9017qKMd3uDBE5W1wVyOleM8Yr-7IaUztQOxyjKbPdsBU8n1F64zm1-RzEriYSq1G6oJfqEkDNc1q0oThM_zN72056vLi5xWUHRbsN7CzZ5WeGQ5vcpUE3PqRquw
{"active":true,"iss":"http://127.0.0.1:8081","sub":"admin2","exp":1728289894,"jti":"2bd77f2a-0ea5-4bfb-8455-c0efc43707f7","scope":[{"rn":"my_service","role":"admin"}]}
```