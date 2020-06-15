ui = true

listener "tcp" {
  address          = "0.0.0.0:8200"
  cluster_address  = "0.0.0.0:8201"
  tls_disable      = "true"
  telemetry {
    unauthenticated_metrics_access = true
  }
}

storage "consul" {
  address = "rks-consul:8500"
  path    = "vault/"
}

telemetry {
  prometheus_retention_time = "30s",
  disable_hostname = true
}


api_addr = "http://rks-vault:8200"
cluster_addr = "http://0.0.0.0:8201"
