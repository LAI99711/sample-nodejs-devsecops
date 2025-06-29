package main

deny[msg] {
  input.kind == "Pod"
  not input.spec.securityContext.runAsNonRoot                  # ou runAsUser != 0
  msg := "Pod niveau – execution en tant que root interdite"
}

deny[msg] {
  input.kind == "Pod"
  some i
  container := input.spec.containers[i]
  container.securityContext.runAsUser == 0
  msg := sprintf("Conteneur « %v » runAsUser: 0 (root)", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "Deployment niveau – runAsNonRoot doit être true"
}

