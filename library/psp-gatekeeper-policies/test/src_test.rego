package ritatest

test_replicator_update_namespace_denied {
    results := deny with input as {
        "request": {
            "operation": "UPDATE",
            "kind": {
                "kind": "Namespace"
            },
            "userInfo": {
              "username": "system:serviceaccount:infra:kubernetes-replicator",
              "groups": [
                "system:serviceaccounts",
                "system:serviceaccounts:infra",
                "system:authenticated"
              ]
            },
            "object": {
            }
        }
    }
    count(results) == 0
    
}