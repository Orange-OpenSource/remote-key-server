/** @file

  RKS plugin for Apache Traffic Server

  uses curl for http communication with RKS and nlohmann/json for json decoding
  curl https: https://curl.haxx.se/libcurl/c/https.html
  curl header: https://curl.haxx.se/libcurl/c/httpcustomheader.html
  json library: https://github.com/nlohmann/json

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include <cstdio>
#include <memory.h>
#include <cinttypes>
#include <ts/ts.h>
#include <iostream>
#include <string>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <curl/curl.h>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

#define PLUGIN_NAME "rks"
#define PCP "[" PLUGIN_NAME "] "

namespace
{
char GROUP_TOKEN[100];
char NODE_ID[100];
char RKS_HOST_PORT[100];
// Write curl http response body inside a string
// https://stackoverflow.com/a/61805520
size_t
writefunc(void *ptr, size_t size, size_t nmemb, std::string *s)
{
  s->append(static_cast<char *>(ptr), size*nmemb);
  return size*nmemb;
}

// register the server to the RKS using the configuration variables GROUP_TOKEN and NODE_ID
std::string
register_node() {
  CURL *curl;
  CURLcode res;
  json json_body;

  TSDebug(PLUGIN_NAME, "register node to RKS");

  curl = curl_easy_init();
  if(curl) {
    struct curl_slist *headers = nullptr;
    std::string raw_body;

    // build query url
    char url_buffer[200];
    snprintf(url_buffer, 200, "https://%s/rks/v1/node", RKS_HOST_PORT);
    curl_easy_setopt(curl, CURLOPT_URL, url_buffer);

    // http post
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    // add node-token and X-LCDN-nodeId headers
    char node_token_header[120];
    snprintf(node_token_header, 120, "X-Vault-Token: %s", GROUP_TOKEN);
    headers = curl_slist_append(headers, node_token_header);

    snprintf(node_token_header, 120, "X-LCDN-nodeId: %s", NODE_ID);
    headers = curl_slist_append(headers, node_token_header);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // authorize insecure https (self signed certificate, invalid Common Name or Alternative name)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    // write response body (normally json formatted) inside raw_body string
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &raw_body);

    // Perform the request, res will get the return code
    res = curl_easy_perform(curl);

    // cleanup headers and curl request
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    /* Check for errors */
    if(res != CURLE_OK) {
      TSError("curl_easy_perform() failed: %s", curl_easy_strerror(res));
      return std::string();
    }

    // check curl status code
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 201) {
      TSError("Got %ld code: %s", response_code, raw_body.c_str());
      return std::string();
    }

    // Parse json body
    json_body = json::parse(raw_body);
  }

  TSDebug(PLUGIN_NAME, "node registered");
  return json_body["nodeToken"].get<std::string>();
}

// get secret from rks based on given servername
json
fetch_secret(const char* servername, const char* node_token) {
  CURL *curl;
  CURLcode res;
  json json_body;

  TSDebug(PLUGIN_NAME, "fetch secret for %s from RKS", servername);

  curl = curl_easy_init();
  if(curl) {
    struct curl_slist *headers = nullptr;
    std::string raw_body;

    // build query url
    char url_buffer[200];
    snprintf(url_buffer, 200, "https://%s/rks/v1/secret/%s", RKS_HOST_PORT, servername);
    curl_easy_setopt(curl, CURLOPT_URL, url_buffer);

    // add node-token header
    char node_token_header[100];
    snprintf(node_token_header, 100, "X-Vault-Token: %s", node_token);
    headers = curl_slist_append(headers, node_token_header);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // authorize insecure https (self signed certificate, invalid Common Name or Alternative name)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    // write response body (normally json formatted) inside raw_body string
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &raw_body);

    // Perform the request, res will get the return code
    res = curl_easy_perform(curl);

    // cleanup headers and curl request
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    /* Check for errors */
    if(res != CURLE_OK) {
      TSError("curl_easy_perform() failed: %s", curl_easy_strerror(res));
      return nullptr;
    }

    // check curl status code
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200) {
      TSError("Got %ld code: %s", response_code, raw_body.c_str());
      return nullptr;
    }

    // Parse json body
    json_body = json::parse(raw_body);
  }

  TSDebug(PLUGIN_NAME, "%s secret fetched", servername);
  return json_body["data"];
}

// traffic server callback on TLS handshake
// we get the servername indication and query the corresponding certificate/private key on the RKS
// inspiration from: https://github.com/apache/trafficserver/blob/master/example/plugins/c-api/ssl_sni/ssl_sni.cc
int
CB_rks(TSCont /* contp */, TSEvent /* event */, void *edata)
{
  TSVConn ssl_vc         = reinterpret_cast<TSVConn>(edata);
  TSSslConnection sslobj = TSVConnSSLConnectionGet(ssl_vc); // FIXME: this is correct on 8.0.2 but not on 8.0.8, the name changed to TSVConnSslConnectionGet
  SSL *ssl               = reinterpret_cast<SSL *>(sslobj);
  const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

  TSDebug(PLUGIN_NAME, "https handshake with sni: %s", servername);
  if (servername != nullptr) {
    if(sslobj) {
      // TODO: register once and cache node_token for the returned TTL
      std::string node_token = register_node();
      if (node_token.empty()) {
        // didn't get a token back, could be a group token problem or connectivity or ...
        TSVConnClose(ssl_vc); // the handshake hangs out if it is not reenabled here
        return TS_ERROR;
      }

      // TODO: store secret locally for its specified TTL
      auto secret = fetch_secret(servername, node_token.c_str());
      if (secret == nullptr) {
        // No secret found on RKS or RKS error
        // May fallback to a default certificate here instead of erroring
        TSVConnReenable(ssl_vc);
        return TS_ERROR;
      }

      // TSDebug(PLUGIN_NAME, "%s", secret.dump().c_str()); // dump certificate and private key to log

      // create a new context as reusing the previous one like this:
      // SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
      // doesn't seem to work
      SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

      // Read cert and pkey into their respective openssl structs
      // https://stackoverflow.com/a/6968171
      BIO *bio;
      X509 *certificate;
      RSA *private_key;

      bio = BIO_new(BIO_s_mem());

      // get certificate from json body, convert to c_string for openssl
      BIO_puts(bio, secret["certificate"].get<std::string>().c_str());
      certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);

      // same for private_key
      BIO_puts(bio, secret["private_key"].get<std::string>().c_str());
      private_key = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);

      // use certificate and private key in the openssl context
      if (SSL_CTX_use_certificate(ctx, certificate) <= 0) {
        TSDebug(PLUGIN_NAME, "certificate not found: %s", servername);
        return TS_ERROR;
      }

      if (SSL_CTX_use_RSAPrivateKey(ctx, private_key) <= 0) {
        TSDebug(PLUGIN_NAME, "private key not found: %s", servername);
        return TS_ERROR;
      }

      // verify private key corresponds to certificate
      if ( !SSL_CTX_check_private_key(ctx) )
      {
        TSDebug(PLUGIN_NAME,"Private key does not match the public certificate");
        return TS_ERROR;
      }

      // set the created context for the current https session
      SSL_set_SSL_CTX(ssl, ctx);
    }
  }

  // All done, reactivate things
  TSVConnReenable(ssl_vc);
  return TS_SUCCESS;
}

} // namespace

// Called by ATS as our initialization point
void
TSPluginInit(int argc, const char *argv[])
{
  bool success = false;
  TSPluginRegistrationInfo info;
  TSCont cb_cert = nullptr; // Certificate callback continuation

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Orange";
  info.support_email = "glenn.feunteun@orange.com";

  if (TS_SUCCESS != TSPluginRegister(&info)) {
    TSError(PCP "registration failed");
  } else if (TSTrafficServerVersionGetMajor() < 7) {
    TSError(PCP "requires Traffic Server 7.0 or later");
  } else if (nullptr == (cb_cert = TSContCreate(&CB_rks, TSMutexCreate()))) {
    TSError(PCP "Failed to create cert callback");
  } else {
    TSHttpHookAdd(TS_SSL_CERT_HOOK, cb_cert);
    success = true;
  }

  if (!success) {
    TSError(PCP "not initialized");
  }
  TSDebug(PLUGIN_NAME, "Plugin %s", success ? "online" : "offline");

  if (argc != 4) {
    TSError(PCP "not enough arguments, need rks_host, group_token and node_id in plugin.config");
    return;
  }

  for (int i = 1; i < argc; i++) {
    TSDebug(PLUGIN_NAME, "Config: %s", argv[i]);
  }

  // get RKS plugin config specified in /etc/trafficserver/plugin.config
  strcpy(RKS_HOST_PORT, argv[1]);
  strcpy(GROUP_TOKEN, argv[2]);
  strcpy(NODE_ID, argv[3]);

  curl_global_init(CURL_GLOBAL_DEFAULT); // not sure this belongs here
  // we never call curl_global_cleanup(); not sure if it is ok

  return;
}
