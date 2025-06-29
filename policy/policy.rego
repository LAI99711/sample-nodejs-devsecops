package main

deny[msg] {
  input.kind == "Pod"
  sc := input.spec.containers[_].securityContext
  sc.runAsUser == 0
  msg := "Exécution en tant que root interdite (runAsUser: 0)"
}

