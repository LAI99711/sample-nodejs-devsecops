package main

# ❌ Refuser si un Pod n'utilise pas runAsNonRoot
deny[msg] {
  input.kind == "Pod"
  not input.spec.securityContext.runAsNonRoot
  msg := "Pod : runAsNonRoot doit être défini à true"
}

# ❌ Refuser si un conteneur est exécuté en tant que root
deny[msg] {
  input.kind == "Pod"
  some i
  input.spec.containers[i].securityContext.runAsUser == 0
  msg := sprintf("Conteneur %q exécute en tant que root (runAsUser: 0)", [input.spec.containers[i].name])
}

# ❌ Refuser si un Deployment n'a pas runAsNonRoot activé
deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "Deployment : runAsNonRoot doit être défini à true"
}

