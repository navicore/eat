#!/bin/bash

set -e

NAMESPACE="audio-latency-tracker"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-}"

echo "Deploying Audio Latency Tracker..."

# Build and push image if registry is specified
if [ -n "$REGISTRY" ]; then
    echo "Building Docker image..."
    docker build -t audio-latency-tracker:$IMAGE_TAG .
    
    echo "Tagging and pushing to registry..."
    docker tag audio-latency-tracker:$IMAGE_TAG $REGISTRY/audio-latency-tracker:$IMAGE_TAG
    docker push $REGISTRY/audio-latency-tracker:$IMAGE_TAG
    
    # Update DaemonSet image
    kubectl patch daemonset audio-latency-tracker \
        -n $NAMESPACE \
        -p '{"spec":{"template":{"spec":{"containers":[{"name":"audio-latency-tracker","image":"'$REGISTRY'/audio-latency-tracker:'$IMAGE_TAG'"}]}}}}'
else
    echo "No registry specified, assuming image is already available in cluster"
fi

# Apply manifests
echo "Applying Kubernetes manifests..."
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/configmap.yaml
kubectl apply -f deploy/daemonset.yaml
kubectl apply -f deploy/service.yaml

# Apply ServiceMonitor if Prometheus operator is installed
if kubectl api-resources | grep -q servicemonitors.monitoring.coreos.com; then
    echo "Prometheus operator detected, applying ServiceMonitor..."
    kubectl apply -f deploy/servicemonitor.yaml
else
    echo "Prometheus operator not detected, skipping ServiceMonitor"
fi

echo "Waiting for DaemonSet to be ready..."
kubectl rollout status daemonset/audio-latency-tracker -n $NAMESPACE

echo "Deployment complete!"
echo ""
echo "To view logs:"
echo "  kubectl logs -n $NAMESPACE -l app=audio-latency-tracker -f"
echo ""
echo "To check metrics:"
echo "  kubectl port-forward -n $NAMESPACE daemonset/audio-latency-tracker 9090:9090"
echo "  curl http://localhost:9090/metrics"