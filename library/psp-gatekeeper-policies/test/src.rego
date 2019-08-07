package ritatest

deny[msg] {
    allowedResources = {"Secret", "Configmap", "Role", "Rolebinding"}
    allowedVerbs = {"UPDATE"}

    username := input.request.userInfo.username
    resource := input.request.kind.kind
    verb := input.request.operation
    
    resourceIntersection := allowedResources & {resource}
    verbIntersection := allowedVerbs & {verb}
    
    username == "system:serviceaccount:infra:kubernetes-replicator"
    count(resourceIntersection) == 0 || count(verbIntersection) == 0
    msg := "Replicator is not authorized"
}