package main

# Refuser si le Pod ne définit pas runAsNonRoot
deny[msg] contains msg if {
  input.kind == "Pod"
  not input.spec.securityContext.runAsNonRoot
  msg = "Pod : runAsNonRoot doit être défini à true"
}

# Refuser si un conteneur du Pod utilise runAsUser = 0 (root)
deny[msg] contains msg if {
  input.kind == "Pod"
  some i
  input.spec.containers[i].securityContext.runAsUser == 0
  msg = "Conteneur exécuté en tant que root (runAsUser: 0)"
}

# Refuser si un Deployment ne définit pas runAsNonRoot
deny[msg] contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg = "Deployment : runAsNonRoot doit être défini à true"
}

