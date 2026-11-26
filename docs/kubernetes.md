# Kubernetes, Cilium and KubeVirt observation

Kavach already has container and Kubernetes depth in the Unix content pack (`ux2-*`).

## Planned enhancements (observation-only)

- Additional rules for pod-to-pod traffic patterns, network-policy denials (as log events), and KubeVirt VM lifecycle.
- Optional offline ingestion of Cilium Hubble flow exports.
- Console fleet view that distinguishes nodes, pods and VirtualMachines.

All new detectors will ship with positive/negative examples in the content harness.

See [ROADMAP.md](ROADMAP.md#5-richer-kubernetes--cilium--kubevirt-observation).
