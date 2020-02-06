ui = true

listener "tcp" {
  address          = "0.0.0.0:8200"
  cluster_address  = "0.0.0.0:8201"
  tls_disable      = "true"
}

storage "consul" {
  address = "rks-consul:8500"
  path    = "vault/"
}

api_addr = "http://rks-vault:8200"
cluster_addr = "http://0.0.0.0:8201"
