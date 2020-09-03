require "resty.core"
require "resty.core.shdict"

local resty_lock = require "resty.lock"
--local open = io.open
local ssl = require "ngx.ssl"
local http = require "resty.http"
local cjson = require "cjson"
local httpc = http.new()

-- Recover env variables
-- They need to be authorized in nginx.conf file with the env directive
local rks_ip = os.getenv("RKS_IP")
local rks_port = os.getenv("RKS_PORT")
local group_token = os.getenv("RKS_GROUP_TOKEN")
local node_id = os.getenv("RKS_NODE_ID")

-- Tries to get the given cache_key from the given cache
-- If the key is not found, the key is locked and the lock returned to allow a set operation
-- In case the lock is returned, IT MUST BE CLOSED AFTERWARD
-- Return cache_data, lock, error
local function get_from_cache_or_acquire_lock(cache, cache_key)
  -- adapted from https://github.com/openresty/lua-resty-lock#for-cache-locks
  -- step 1 Try to get cache_key from cache:
  local cache_data, err = cache:get(cache_key)
  if cache_data then
    ngx.log(ngx.NOTICE, "Found " ..cache_key.. ": " .. cache_data)
    return cache_data, nil, nil
  end

  if err then
    ngx.log(ngx.ERR, "failed to get ", cache_key, " from shm: ", err)
    return nil, nil, ngx.exit(ngx.ERROR)
  end

  -- cache miss, try to lock the key
  -- step 2:
  ngx.log(ngx.NOTICE, "Cache miss for ", cache_key)

  local lock, err = resty_lock:new("my_locks")
  if not lock then
    ngx.log(ngx.ERR, "failed to create lock: ", err)
    return nil, nil, ngx.exit(ngx.ERROR)
  end

  local elapsed, err = lock:lock(cache_key)
  if not elapsed then
    ngx.log(ngx.ERR, "failed to acquire the lock: ", err)
    return nil, nil, ngx.exit(ngx.ERROR)
  end

  -- step 3:
  -- someone might have already put the value into the cache between the key check and the lock
  -- so we check it here again:
  cache_data, err = cache:get(cache_key)
  if cache_data then
    -- Got it, unlock and return
    local ok, err = lock:unlock()
    if not ok then
      ngx.log(ngx.ERR, "failed to unlock: ", err)
      return nil, nil, ngx.exit(ngx.ERROR)
    end

    ngx.log(ngx.NOTICE, "result: ", cache_data)
    return cache_data, nil, nil
  end

  if err then
    ngx.log(ngx.ERR, "failed to get ", cache_key, " from shm: ", err)
    return nil, nil, ngx.exit(ngx.ERROR)
  end

  -- Did not get cache_key, return the lock
  return nil, lock, nil
end

-- Set a cache_key with cache_data for cache_duration in given cache using given lock
-- Return error
local function set_and_unlock(cache, lock, cache_key, cache_data, cache_duration)
  local ok, err = cache:set(cache_key, cache_data, cache_duration)
  if not ok then
    ngx.log(ngx.ERR, err)
    local ok, err = lock:unlock()
    if not ok then
      ngx.log(ngx.ERR, "failed to unlock")
      return ngx.exit(ngx.ERROR)
    end

    ngx.log(ngx.ERR, "failed to update shm cache: ", ok, err)
    return ngx.exit(ngx.ERROR)
  end

  local ok, err = lock:unlock()
  if not ok then
    ngx.log(ngx.ERR, "failed to unlock", " err: ", err)
    return ngx.exit(ngx.ERROR)
  end

  return nil
end

-- Register node on the RKS
local function register_node()
  ngx.log(ngx.NOTICE, "Register Node to RKS at: "..rks_ip..":"..rks_port.. " with X-Vault-Token: ".. group_token)
  local res, err = httpc:request_uri("https://"..rks_ip..":"..rks_port.."/rks/v1/node", {
    method = "POST",
    headers = {
      ["X-Vault-Token"] = group_token,
      ["X-LCDN-nodeId"] = node_id
    },
    ssl_verify = false
  })

  if not res then
    ngx.log(ngx.ERR, "failed to request: ", err)
    return nil
  end

  return cjson.decode(res.body)
end

-- Get node token
-- Tries cache first, register on RKS if no entry found
local function RKS_get_node_token()
  local cache = ngx.shared.secrets

  local raw_node_token, lock, err = get_from_cache_or_acquire_lock(cache, 'nodeToken')
  if err then
    return nil, err
  end

  if lock then
    local node_token = register_node()

    err = set_and_unlock(cache, lock, "nodeToken", cjson.encode(node_token), node_token.ttl - 1)
    if err then
      return nil, err
    end
    return node_token.nodeToken, nil
  end

  return cjson.decode(raw_node_token).nodeToken, nil
end

-- Get secret associated with fqdn
-- Tries cache first and query RKS if no entry found
local function RKS_get_secret(fqdn)
  local cache = ngx.shared.secrets

  ngx.log(ngx.NOTICE, "Free shm space: ", cache:free_space())

  local node_token, err = RKS_get_node_token()

  if not node_token then
    ngx.log(ngx.NOTICE, "bug", err)
    return nil, ngx.exit(ngx.ERROR)
  end

  local raw_secret, lock, err = get_from_cache_or_acquire_lock(cache, fqdn)
  if err then
    return nil, err
  end

  local secret
  if lock then
    ngx.log(ngx.NOTICE, "Accessing RKS at: "..rks_ip..":"..rks_port.. " with X-Vault-Token: ".. node_token)

    local res, err = httpc:request_uri("https://"..rks_ip..":" ..rks_port.."/rks/v1/secret/" .. fqdn, {
      headers = {
        ["X-Vault-Token"] = node_token
      },
      ssl_verify = false
    })

    if not res then
      ngx.log(ngx.ERR, "failed to request: ", err)
      local ok, err = lock:unlock()
      if not ok then
        ngx.log(ngx.ERR, "failed to unlock: ", err)
        return nil, ngx.exit(ngx.ERROR)
      end
      ngx.say("No secret found")
      return nil, nil
    end
    secret = cjson.decode(res.body)

    err = set_and_unlock(cache, lock, fqdn, res.body, secret.data.meta.ttl - 1)
    if err then
      return nil, err
    end
    return secret, nil
  end

  return cjson.decode(raw_secret), nil
end

ngx.log(ngx.NOTICE, "Received SSL Handshake. Load secret from RKS")

-- clear the fallback certificates and private keys
-- set by the ssl_certificate and ssl_certificate_key
-- directives above:
local ok, err = ssl.clear_certs()
if not ok then
  ngx.log(ngx.ERR, "failed to clear existing (fallback) certificates", " err: ", err)
  return ngx.exit(ngx.ERROR)
end

-- Print SNI
local name, err = ssl.server_name()
if not name then
  ngx.log(ngx.ERR, err)
  return ngx.exit(ngx.ERROR)
end
ngx.log(ngx.NOTICE, "Got SNI: ", name)

-- Recover secret from local cache or remote RKS
local secret, err = RKS_get_secret(name)
if not secret then
  ngx.log(ngx.ERR, "no secret for " .. name.. " found" .. err)
  return ngx.exit(ngx.ERROR)
end

-- Set certificate and private_key to finalize HTTPS handshake
local pem_cert = secret.data.certificate
local pem_priv_key = secret.data.private_key
local cert, err = ssl.parse_pem_cert(pem_cert)
if not cert then
  ngx.log(ngx.ERR, err)
  return ngx.exit(ngx.ERROR)
end

local ok, err = ssl.set_cert(cert)
if not ok then
  ngx.log(ngx.ERR, "failed to set cert: ", err)
  return ngx.exit(ngx.ERROR)
end

local priv_key, err = ssl.parse_pem_priv_key(pem_priv_key)
if not priv_key then
  ngx.log(ngx.ERR, err)
  return ngx.exit(ngx.ERROR)
end

local ok, err = ssl.set_priv_key(priv_key)
if not ok then
  ngx.log(ngx.ERR, "failed to set private key: ", err)
  return ngx.exit(ngx.ERROR)
end


-- Annex - Load certificate and private_key from file
-- Get Cert and Private key from sni name from file
-- local pem_cert_file = open("/etc/nginx/ssl/" .. name .. ".crt", "rb") -- r read mode and b binary mode
-- if not pem_cert_file then
--   return nil
-- end
-- local pem_cert = pem_cert_file:read "*all" -- *a or *all reads the whole file
-- pem_cert_file:close()
-- ngx.log(ngx.NOTICE, pem_cert)
--
-- local pem_priv_key_file = open("/etc/nginx/ssl/" .. name .. ".key", "rb") -- r read mode and b binary mode
-- if not pem_priv_key_file then
--   ngx.log(ngx.ERR, "pem_priv_key_file not found")
--   return nil
-- end
-- local pem_priv_key = pem_priv_key_file:read "*all" -- *a or *all reads the whole file
-- pem_priv_key_file:close()
-- ngx.log(ngx.NOTICE, pem_priv_key)
