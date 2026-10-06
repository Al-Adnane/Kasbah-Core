#!/bin/bash
set -e

# Kasbah Kubernetes Deployment Script
# Usage: ./deploy.sh [--namespace NAMESPACE] [--image-tag TAG]

NAMESPACE="${NAMESPACE:-kasbah}"
IMAGE_TAG="${IMAGE_TAG:-9.1.0}"
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_RED='\033[0;31m'
COLOR_NC='\033[0m' # No Color

echo -e "${COLOR_YELLOW}==================================${COLOR_NC}"
echo -e "${COLOR_YELLOW}Kasbah Kubernetes Deployment${COLOR_NC}"
echo -e "${COLOR_YELLOW}==================================${COLOR_NC}"
echo ""
echo "Namespace: ${COLOR_GREEN}${NAMESPACE}${COLOR_NC}"
echo "Image Tag: ${COLOR_GREEN}${IMAGE_TAG}${COLOR_NC}"
echo ""

# Check kubectl
if ! command -v kubectl &> /dev/null; then
    echo -e "${COLOR_RED}Error: kubectl is not installed${COLOR_NC}"
    exit 1
fi

# Check cluster connection
if ! kubectl cluster-info &> /dev/null; then
    echo -e "${COLOR_RED}Error: Cannot connect to Kubernetes cluster${COLOR_NC}"
    exit 1
fi

echo -e "${COLOR_GREEN}✓${COLOR_NC} Connected to Kubernetes cluster"

# Create namespace if not exists
echo "Creating namespace..."
kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
echo -e "${COLOR_GREEN}✓${COLOR_NC} Namespace ${NAMESPACE} ready"

# Apply RBAC
echo "Applying RBAC configuration..."
kubectl apply -f deployment/k8s/rbac.yaml -n ${NAMESPACE}
echo -e "${COLOR_GREEN}✓${COLOR_NC} RBAC configured"

# Apply ConfigMap
echo "Creating ConfigMap..."
kubectl create configmap kasbah-config \
  --from-literal=NODE_ENV=production \
  --from-literal=LOG_LEVEL=info \
  --dry-run=client -o yaml | kubectl apply -f -
echo -e "${COLOR_GREEN}✓${COLOR_NC} ConfigMap created"

# Apply Deployment
echo "Deploying application..."
kubectl apply -f deployment/k8s/deployment.yaml -n ${NAMESPACE}
echo -e "${COLOR_GREEN}✓${COLOR_NC} Deployment created"

# Apply Service + HPA
echo "Creating service and autoscaler..."
kubectl apply -f deployment/k8s/service-hpa.yaml -n ${NAMESPACE}
echo -e "${COLOR_GREEN}✓${COLOR_NC} Service + HPA created"

# Apply Ingress
echo "Configuring ingress..."
kubectl apply -f deployment/k8s/ingress.yaml -n ${NAMESPACE}
echo -e "${COLOR_GREEN}✓${COLOR_NC} Ingress configured"

# Wait for rollout
echo ""
echo -e "${COLOR_YELLOW}Waiting for deployment to complete...${COLOR_NC}"
kubectl rollout status deployment/kasbah-api -n ${NAMESPACE} --timeout=300s

# Show status
echo ""
echo -e "${COLOR_GREEN}==================================${COLOR_NC}"
echo -e "${COLOR_GREEN}Deployment Complete!${COLOR_NC}"
echo -e "${COLOR_GREEN}==================================${COLOR_NC}"
echo ""
echo "Pods:"
kubectl get pods -n ${NAMESPACE} -l app=kasbah-api
echo ""
echo "Services:"
kubectl get svc -n ${NAMESPACE}
echo ""
echo "To view logs:"
echo "  kubectl logs -n ${NAMESPACE} -l app=kasbah-api -f"
echo ""
echo "To access the API:"
echo "  kubectl port-forward -n ${NAMESPACE} svc/kasbah-api 3000:80"
