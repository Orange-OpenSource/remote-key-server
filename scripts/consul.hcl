datacenter = "dc1"
data_dir = "/opt/consul"
disable_update_check = true
server = true

addresses {
  http = "0.0.0.0"
}

telemetry {
  prometheus_retention_time = "60s",
  disable_hostname = true
}
