terraform {
  required_version = ">= 1.5.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
  }
}

# Connects with your local kubeconfig by default:
#   terraform init && terraform apply -var="image=kasbah-api:9.1.0"
variable "image" {
  description = "Kasbah API container image"
  type        = string
  default     = "kasbah-api:9.1.0"
}

variable "namespace" {
  description = "Kubernetes namespace"
  type        = string
  default     = "kasbah"
}

variable "proof_key" {
  description = "KASBAH_PROOF_KEY value (receipt signing secret)"
  type        = string
  sensitive   = true
}

resource "kubernetes_namespace" "kasbah" {
  metadata { name = var.namespace }
}

resource "kubernetes_secret" "kasbah_secrets" {
  metadata {
    name      = "kasbah-secrets"
    namespace = kubernetes_namespace.kasbah.metadata[0].name
  }
  data = { proof-key = var.proof_key }
}

resource "kubernetes_deployment" "api" {
  metadata {
    name      = "kasbah-api"
    namespace = kubernetes_namespace.kasbah.metadata[0].name
  }
  spec {
    replicas = 2
    selector { match_labels = { app = "kasbah-api" } }
    template {
      metadata { labels = { app = "kasbah-api" } }
      spec {
        container {
          name  = "api"
          image = var.image
          port { container_port = 8788 }
          env {
            name  = "NODE_ENV"
            value = "production"
          }
          env {
            name  = "PORT"
            value = "8788"
          }
          env {
            name = "KASBAH_PROOF_KEY"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.kasbah_secrets.metadata[0].name
                key  = "proof-key"
              }
            }
          }
          liveness_probe {
            http_get {
              path = "/v1/health"
              port = 8788
            }
            initial_delay_seconds = 20
            period_seconds        = 30
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "api" {
  metadata {
    name      = "kasbah-api"
    namespace = kubernetes_namespace.kasbah.metadata[0].name
  }
  spec {
    selector = { app = "kasbah-api" }
    port {
      port        = 80
      target_port = 8788
    }
  }
}
