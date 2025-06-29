package main

deny[msg] {
  input.kind == "Pod"
  some i
  input.spec.containers[i].securityContext.runAsUser == 0
  msg := "Exécution en tant que root interdite (runAsUser: 0)"
}

