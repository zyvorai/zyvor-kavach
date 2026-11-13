package edr

// cloudHuntPacks adds cloud, container and Kubernetes hunts. Terms are lowercase
// substrings over exe+command+rule+description. Observation only: they describe
// what to look for, never what to do. Ids use the hc- prefix.
var cloudHuntPacks = []HuntPack{
	{"hc-k8s-secret-bulk-read", "Kubernetes Secret bulk reads", "T1552.007", "credential-access", []string{"get secrets -a", "get secret --all-namespaces", "get secrets --all-namespaces", "etcdctl get /registry/secrets"}},
	{"hc-k8s-rbac-grant", "Cluster role binding to powerful roles", "T1098.006", "privilege-escalation", []string{"create clusterrolebinding", "cluster-admin", "create rolebinding --clusterrole=admin", "system:masters"}},
	{"hc-k8s-node-shell", "Node-level shell from Kubernetes tooling", "T1611", "privilege-escalation", []string{"kubectl debug node/", "nsenter --target 1", "kubectl-node-shell", "node-shell"}},
	{"hc-k8s-sa-token-theft", "Service account token handling", "T1528", "credential-access", []string{"serviceaccount/token", "create token", "eks.amazonaws.com/serviceaccount", "aws_web_identity_token_file"}},
	{"hc-k8s-kubelet-api-abuse", "Direct kubelet API use", "T1609", "execution", []string{":10250/run", ":10250/exec", ":10250/pods", "kubeletctl", ":10255/pods"}},
	{"hc-k8s-static-pod-drop", "Static pod manifest persistence", "T1053.007", "persistence", []string{"/etc/kubernetes/manifests/", "staticpodpath", "static-pod-path"}},
	{"hc-k8s-admission-tamper", "Admission webhook or policy tampering", "T1562.001", "defense-evasion", []string{"delete validatingwebhookconfiguration", "delete mutatingwebhookconfiguration", "kubectl delete clusterpolicy", "kubectl delete constrainttemplate"}},
	{"hc-k8s-audit-evasion", "Audit trail removal in clusters", "T1070", "defense-evasion", []string{"kubectl delete events", "audit-policy", "--audit-log-path=", "kubectl delete event"}},
	{"hc-k8s-privileged-workloads", "Privileged or host-namespace workloads", "T1610", "execution", []string{"privileged: true", "hostpid: true", "hostipc: true", "--overrides={\"spec\":{\"hostpid", "allowprivilegeescalation: true"}},
	{"hc-k8s-hostpath-sensitive", "hostPath mounts of sensitive node paths", "T1611", "privilege-escalation", []string{"hostpath:", "path: /var/run/docker.sock", "path: /etc/kubernetes", "path: /var/lib/kubelet"}},
	{"hc-k8s-api-recon-tools", "Kubernetes offensive recon tools", "T1613", "discovery", []string{"kube-hunter", "kubehunter", "peirates", "kdigger", "kubesploit", "kubestroyer"}},
	{"hc-k8s-port-scanning", "Scans for control-plane ports", "T1046", "discovery", []string{"nmap -p 10250", "nmap -p 2379", "masscan -p 10250", "-p 6443,10250"}},
	{"hc-k8s-aws-auth-edit", "EKS identity mapping edits", "T1098", "privilege-escalation", []string{"configmap aws-auth", "aws-auth -n kube-system", "eks update-kubeconfig", "eks create-access-entry"}},
	{"hc-container-escape-primitives", "Container escape primitives", "T1611", "privilege-escalation", []string{"release_agent", "core_pattern", "/proc/1/root", "#!/proc/self/exe", "mknod /dev/"}},
	{"hc-container-escape-toolkits", "Container breakout toolkits", "T1611", "privilege-escalation", []string{"deepce", "amicontained", "cdk evaluate", "cdk run", "botb "}},
	{"hc-container-docker-sock-mount", "Docker socket exposed to containers", "T1611", "privilege-escalation", []string{"/var/run/docker.sock:", "-v /run/docker.sock", "--unix-socket /var/run/docker.sock", "docker.sock:/var/run"}},
	{"hc-container-privileged-run", "Privileged container launches", "T1610", "execution", []string{"--privileged", "--cap-add=sys_admin", "--cap-add sys_admin", "--security-opt seccomp=unconfined", "--pid=host"}},
	{"hc-container-remote-api", "Remote container daemon use", "T1610", "lateral-movement", []string{"docker -h tcp://", "dockerd -h tcp://0.0.0.0", ":2375/containers", ":2375/images", "docker --host tcp://"}},
	{"hc-container-image-exfil", "Container image export and push", "T1567", "exfiltration", []string{"docker save", "skopeo copy docker://", "crane push", "docker push docker.io/", "ctr images push"}},
	{"hc-container-security-agent-stop", "Container security agent shutdown", "T1562.001", "defense-evasion", []string{"docker stop falco", "docker rm -f falco", "systemctl stop falco", "kubectl scale ds/falco", "systemctl stop sysdig", "docker stop twistlock"}},
	{"hc-container-mining", "Mining workloads in containers", "T1496", "impact", []string{"metal3d/xmrig", "docker run -d xmrig", "kinsing", "kdevtmpfsi", "stratum+tcp://", "--donate-level"}},
	{"hc-cloud-imds-credential-fetch", "Metadata service credential requests", "T1552.005", "credential-access", []string{"169.254.169.254/latest/meta-data/iam", "latest/api/token", "identity/oauth2/token", "service-accounts/default/token", "169.254.170.2"}},
	{"hc-cloud-credential-file-reads", "Cloud CLI credential store reads", "T1552.001", "credential-access", []string{".aws/credentials", "gcloud/credentials.db", "application_default_credentials", ".azure/msal_token_cache", ".azure/accesstokens.json", ".kube/config"}},
	{"hc-cloud-secret-store-reads", "Cloud secret store reads", "T1555.006", "credential-access", []string{"secretsmanager get-secret-value", "secrets versions access", "keyvault secret show", "ssm get-parameters-by-path", "--with-decryption"}},
	{"hc-cloud-iam-persistence", "New cloud credentials and roles", "T1098.001", "persistence", []string{"iam create-access-key", "keys create", "ad app credential reset", "create-login-profile", "ad sp create-for-rbac"}},
	{"hc-cloud-audit-log-tamper", "Cloud audit log tampering", "T1562.008", "defense-evasion", []string{"cloudtrail stop-logging", "cloudtrail delete-trail", "diagnostic-settings delete", "logging sinks delete", "guardduty delete-detector"}},
	{"hc-cloud-attack-tools", "Cloud post-exploitation tooling", "T1580", "discovery", []string{"pacu ", "enumerate-iam", "azurehound", "roadrecon", "gcp_scanner", "cloudfox", "s3scanner"}},
	{"hc-iac-state-secrets", "Infrastructure-as-code state and secret reads", "T1552.001", "credential-access", []string{"terraform state pull", "terraform.tfstate", "--show-secrets", "terraform output -json", "credentials.tfrc.json"}},
	{"hc-ci-runner-secret-theft", "CI runner secret theft", "T1003.007", "credential-access", []string{"runner.worker", "actions_id_token_request", "actions_runtime_token", "actions-runner/.credentials", "secrets/master.key"}},
	{"hc-ci-supply-chain-publish", "Insecure package and chart sources", "T1195.002", "initial-access", []string{"publish --registry http://", "helm repo add", "helm plugin install http", "pip install --index-url http://", "npm install http://"}},
	{"hc-cloud-guest-agent-abuse", "Cloud guest agent child processes", "T1651", "execution", []string{"ssm-agent-worker", "google_guest_agent", "waagent", "aws ssm start-session", "az vm run-command"}},
	{"hc-cloud-tunnels", "Tunnel brokers from cloud hosts", "T1572", "command-and-control", []string{"cloudflared tunnel", "ngrok tcp", "trycloudflare.com", "tailscale up --authkey", "serveo.net"}},
	{"hc-cloud-bulk-data-pull", "Bulk bucket downloads and uploads", "T1530", "collection", []string{"s3 sync s3://", "s3 cp s3://", "gsutil -m cp -r gs://", "azcopy copy", "rclone sync"}},
}

func init() {
	huntPacks = append(huntPacks, cloudHuntPacks...)
}
