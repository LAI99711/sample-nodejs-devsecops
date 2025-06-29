package main

deny[msg] if {
  input.kind == "Pod"
  not input.spec.securityContext.runAsNonRoot
  msg := "Pod niveau – execution en tant que root interdite"
}

deny[msg] if {
  input.kind == "Pod"
  some i
  input.spec.containers[i].securityContext.runAsUser == 0
  msg := "Conteneur avec runAsUser: 0 (root)"
}

deny[msg] if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "Deployment niveau – runAsNonRoot doit être défini à true"
}

