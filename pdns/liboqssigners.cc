/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "liboqssigners.hh"
#include "misc.hh"
#include <memory>
#include <optional>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"

#include "lock.hh"

#ifdef HAVE_LIBCRYPTO_PQC

static OQS_STATUS lock_sk(void* mutex)
{
  if (mutex == NULL)
    return OQS_ERROR;
  if (pthread_mutex_lock((pthread_mutex_t*)mutex) == 0)
    return OQS_SUCCESS;
  else
    return OQS_ERROR;
}

static OQS_STATUS unlock_sk(void* mutex)
{
  if (mutex == NULL)
    return OQS_ERROR;
  if (pthread_mutex_unlock((pthread_mutex_t*)mutex) == 0)
    return OQS_SUCCESS;
  else
    return OQS_ERROR;
}

static OQS_STATUS save_sk(unsigned char* key_buf, size_t buf_len, void* context)
{
  // This callback is designed to update keys on disk. Our key will only live in
  // memory, so it is just a NOOP.
  (void)key_buf;
  (void)buf_len;
  (void)context;
  return OQS_SUCCESS;
}

#endif

#define XMSS_SHA256_H10_oid 0x01
#define XMSS_SHA256_H16_oid 0x02
#define XMSS_SHA256_H20_oid 0x03
#define XMSS_SHA512_H10_oid 0x04
#define XMSS_SHA512_H16_oid 0x05
#define XMSS_SHA512_H20_oid 0x06
#define XMSS_SHAKE128_H10_oid 0x07
#define XMSS_SHAKE128_H16_oid 0x08
#define XMSS_SHAKE128_H20_oid 0x09
#define XMSS_SHAKE256_H10_oid 0x0a
#define XMSS_SHAKE256_H16_oid 0x0b
#define XMSS_SHAKE256_H20_oid 0x0c

const unsigned int alg_xmss_oid[] = {
  XMSS_SHA256_H10_oid,
  XMSS_SHA256_H16_oid,
  XMSS_SHA256_H20_oid,
  XMSS_SHA512_H10_oid,
  XMSS_SHA512_H16_oid,
  XMSS_SHA512_H20_oid,
  XMSS_SHAKE128_H10_oid,
  XMSS_SHAKE128_H16_oid,
  XMSS_SHAKE128_H20_oid,
  XMSS_SHAKE256_H10_oid,
  XMSS_SHAKE256_H16_oid,
  XMSS_SHAKE256_H20_oid,
  0,
};

const char* alg_xmss_oqsname[] = {
  OQS_SIG_STFL_alg_xmss_sha256_h10,
  OQS_SIG_STFL_alg_xmss_sha256_h16,
  OQS_SIG_STFL_alg_xmss_sha256_h20,
  OQS_SIG_STFL_alg_xmss_sha512_h10,
  OQS_SIG_STFL_alg_xmss_sha512_h16,
  OQS_SIG_STFL_alg_xmss_sha512_h20,
  OQS_SIG_STFL_alg_xmss_shake128_h10,
  OQS_SIG_STFL_alg_xmss_shake128_h16,
  OQS_SIG_STFL_alg_xmss_shake128_h20,
  OQS_SIG_STFL_alg_xmss_shake256_h10,
  OQS_SIG_STFL_alg_xmss_shake256_h16,
  OQS_SIG_STFL_alg_xmss_shake256_h20,
  NULL,
};

unsigned int xmss_pdnsname_to_param(const std::string& algorithm)
{
  int param;
  if (pdns_iequals(algorithm, "xmss-sha256-h10"))
    param = XMSS_SHA256_H10_oid;
  else if (pdns_iequals(algorithm, "xmss-sha256-h16"))
    param = XMSS_SHA256_H16_oid;
  else if (pdns_iequals(algorithm, "xmss-sha256-h20"))
    param = XMSS_SHA256_H20_oid;
  else if (pdns_iequals(algorithm, "xmss-sha512-h10"))
    param = XMSS_SHA512_H10_oid;
  else if (pdns_iequals(algorithm, "xmss-sha512-h16"))
    param = XMSS_SHA512_H16_oid;
  else if (pdns_iequals(algorithm, "xmss-sha512-h20"))
    param = XMSS_SHA512_H20_oid;
  else if (pdns_iequals(algorithm, "xmss-shake128-h10"))
    param = XMSS_SHAKE128_H10_oid;
  else if (pdns_iequals(algorithm, "xmss-shake128-h16"))
    param = XMSS_SHAKE128_H16_oid;
  else if (pdns_iequals(algorithm, "xmss-shake128-h20"))
    param = XMSS_SHAKE128_H20_oid;
  else if (pdns_iequals(algorithm, "xmss-shake256-h10"))
    param = XMSS_SHAKE256_H10_oid;
  else if (pdns_iequals(algorithm, "xmss-shake256-h16"))
    param = XMSS_SHAKE256_H16_oid;
  else if (pdns_iequals(algorithm, "xmss-shake256-h20"))
    param = XMSS_SHAKE256_H20_oid;
  else
    throw runtime_error("invalid xmss parameters");
  return param;
}

static std::string xmss_oid_to_oqsname(unsigned int oid)
{
  for (int i = 0; alg_xmss_oid[i] != 0; i++) {
    if (alg_xmss_oid[i] == oid) {
      return alg_xmss_oqsname[i];
    }
  }
  throw runtime_error("unable to find xmss oqsname for oid: " + std::to_string(oid));
}

const int kXmssOidLen = 4;

static unsigned int xmss_key_to_oid(const std::string& key)
{
  const unsigned char* raw_key = reinterpret_cast<const unsigned char*>(key.c_str());
  const size_t raw_key_len = key.length();
  unsigned int oid = 0;
  if (kXmssOidLen > raw_key_len) {
    return 0;
  }
  for (int i = 0; i < kXmssOidLen; i++) {
    oid |= raw_key[kXmssOidLen - i - 1] << (i * 8);
  }
  return oid;
}

#define XMSSMT_SHA256_H20_2_oid 0x01
#define XMSSMT_SHA256_H20_4_oid 0x02
#define XMSSMT_SHA256_H40_2_oid 0x03
#define XMSSMT_SHA256_H40_4_oid 0x04
#define XMSSMT_SHA256_H40_8_oid 0x05
#define XMSSMT_SHA256_H60_3_oid 0x06
#define XMSSMT_SHA256_H60_6_oid 0x07
#define XMSSMT_SHA256_H60_12_oid 0x08
#define XMSSMT_SHAKE128_H20_2_oid 0x11
#define XMSSMT_SHAKE128_H20_4_oid 0x12
#define XMSSMT_SHAKE128_H40_2_oid 0x13
#define XMSSMT_SHAKE128_H40_4_oid 0x14
#define XMSSMT_SHAKE128_H40_8_oid 0x15
#define XMSSMT_SHAKE128_H60_3_oid 0x16
#define XMSSMT_SHAKE128_H60_6_oid 0x17
#define XMSSMT_SHAKE128_H60_12_oid 0x18

const unsigned int alg_xmssmt_oid[] = {
  XMSSMT_SHA256_H20_2_oid,
  XMSSMT_SHA256_H20_4_oid,
  XMSSMT_SHA256_H40_2_oid,
  XMSSMT_SHA256_H40_4_oid,
  XMSSMT_SHA256_H40_8_oid,
  XMSSMT_SHA256_H60_3_oid,
  XMSSMT_SHA256_H60_6_oid,
  XMSSMT_SHA256_H60_12_oid,
  XMSSMT_SHAKE128_H20_2_oid,
  XMSSMT_SHAKE128_H20_4_oid,
  XMSSMT_SHAKE128_H40_2_oid,
  XMSSMT_SHAKE128_H40_4_oid,
  XMSSMT_SHAKE128_H40_8_oid,
  XMSSMT_SHAKE128_H60_3_oid,
  XMSSMT_SHAKE128_H60_6_oid,
  XMSSMT_SHAKE128_H60_12_oid,
  0,
};

const char* alg_xmssmt_oqsname[] = {
  OQS_SIG_STFL_alg_xmssmt_sha256_h20_2,
  OQS_SIG_STFL_alg_xmssmt_sha256_h20_4,
  OQS_SIG_STFL_alg_xmssmt_sha256_h40_2,
  OQS_SIG_STFL_alg_xmssmt_sha256_h40_4,
  OQS_SIG_STFL_alg_xmssmt_sha256_h40_8,
  OQS_SIG_STFL_alg_xmssmt_sha256_h60_3,
  OQS_SIG_STFL_alg_xmssmt_sha256_h60_6,
  OQS_SIG_STFL_alg_xmssmt_sha256_h60_12,
  OQS_SIG_STFL_alg_xmssmt_shake128_h20_2,
  OQS_SIG_STFL_alg_xmssmt_shake128_h20_4,
  OQS_SIG_STFL_alg_xmssmt_shake128_h40_2,
  OQS_SIG_STFL_alg_xmssmt_shake128_h40_4,
  OQS_SIG_STFL_alg_xmssmt_shake128_h40_8,
  OQS_SIG_STFL_alg_xmssmt_shake128_h60_3,
  OQS_SIG_STFL_alg_xmssmt_shake128_h60_6,
  OQS_SIG_STFL_alg_xmssmt_shake128_h60_12,
  NULL,
};

unsigned int xmssmt_pdnsname_to_param(const std::string& algorithm)
{
  int param;
  if (pdns_iequals(algorithm, "xmssmt-sha256-h20-2"))
    param = XMSSMT_SHA256_H20_2_oid;
  else if (pdns_iequals(algorithm, "xmssmt-sha256-h20-4"))
    param = XMSSMT_SHA256_H20_4_oid;
  else if (pdns_iequals(algorithm, "xmssmt-sha256-h40-2"))
    param = XMSSMT_SHA256_H40_2_oid;
  else if (pdns_iequals(algorithm, "xmssmt-sha256-h40-4"))
    param = XMSSMT_SHA256_H40_4_oid;
  else if (pdns_iequals(algorithm, "xmssmt-sha256-h40-8"))
    param = XMSSMT_SHA256_H40_8_oid;
  else if (pdns_iequals(algorithm, "xmssmt-sha256-h60-3"))
    param = XMSSMT_SHA256_H60_3_oid;
  else if (pdns_iequals(algorithm, "xmssmt-sha256-h60-6"))
    param = XMSSMT_SHA256_H60_6_oid;
  else if (pdns_iequals(algorithm, "xmssmt-sha256-h60-12"))
    param = XMSSMT_SHA256_H60_12_oid;
  else if (pdns_iequals(algorithm, "xmssmt-shake128-h20-2"))
    param = XMSSMT_SHAKE128_H20_2_oid;
  else if (pdns_iequals(algorithm, "xmssmt-shake128-h20-4"))
    param = XMSSMT_SHAKE128_H20_4_oid;
  else if (pdns_iequals(algorithm, "xmssmt-shake128-h40-2"))
    param = XMSSMT_SHAKE128_H40_2_oid;
  else if (pdns_iequals(algorithm, "xmssmt-shake128-h40-4"))
    param = XMSSMT_SHAKE128_H40_4_oid;
  else if (pdns_iequals(algorithm, "xmssmt-shake128-h40-8"))
    param = XMSSMT_SHAKE128_H40_8_oid;
  else if (pdns_iequals(algorithm, "xmssmt-shake128-h60-3"))
    param = XMSSMT_SHAKE128_H60_3_oid;
  else if (pdns_iequals(algorithm, "xmssmt-shake128-h60-6"))
    param = XMSSMT_SHAKE128_H60_6_oid;
  else if (pdns_iequals(algorithm, "xmssmt-shake128-h60-12"))
    param = XMSSMT_SHAKE128_H60_12_oid;
  else
    throw runtime_error("invalid xmssmt parameters");
  return param;
}

static std::string xmssmt_oid_to_oqsname(unsigned int oid)
{
  for (int i = 0; alg_xmssmt_oid[i] != 0; i++) {
    if (alg_xmssmt_oid[i] == oid) {
      return alg_xmssmt_oqsname[i];
    }
  }
  throw runtime_error("unable to find xmssmt oqsname for oid: " + std::to_string(oid));
}

static unsigned int xmssmt_key_to_oid(const std::string& key)
{
  return xmss_key_to_oid(key);
}

#ifdef HAVE_LIBCRYPTO_PQC

class LiboqsStflDNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit LiboqsStflDNSCryptoKeyEngine(unsigned int algo) :
    DNSCryptoKeyEngine(algo),
    d_stflprivkey(std::unique_ptr<OQS_SIG_STFL_SECRET_KEY, void (*)(OQS_SIG_STFL_SECRET_KEY*)>(nullptr, OQS_SIG_STFL_SECRET_KEY_free)),
    d_stflctx(std::unique_ptr<OQS_SIG_STFL, void (*)(OQS_SIG_STFL*)>(nullptr, OQS_SIG_STFL_free))
  {
    switch (algo) {
    case DNSSECKeeper::XMSS:
      d_is_xmssmt = false;
      break;
    case DNSSECKeeper::XMSSMT:
      d_is_xmssmt = true;
      break;
    default:
      throw runtime_error(getName() + " wrong algorithm given to XMSS and XMSSMT CryptoKeyEngine");
    }
  }

  ~LiboqsStflDNSCryptoKeyEngine()
  {
    pthread_mutex_destroy(&d_keylock);
  }

  string getName() const override { return "liboqs stateful signatures"; }
  int getBits() const override { return (d_stflctx.get()->length_public_key << 8); }

  void create(unsigned int bits) override;
  [[nodiscard]] storvector_t convertToISCVector() const override;
  [[nodiscard]] std::string sign(const std::string& message) const override;
  [[nodiscard]] bool verify(const std::string& message, const std::string& signature) const override;
  [[nodiscard]] std::string getPublicKeyString() const override;

  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override;
  void fromPublicKeyString(const std::string& content) override;
  [[nodiscard]] bool checkKey(std::optional<std::reference_wrapper<vector<string>>> errorMessages) const override;

  static std::unique_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm)
  {
    return make_unique<LiboqsStflDNSCryptoKeyEngine>(algorithm);
  }

private:
  std::unique_ptr<OQS_SIG_STFL_SECRET_KEY, void (*)(OQS_SIG_STFL_SECRET_KEY*)> d_stflprivkey;
  std::unique_ptr<OQS_SIG_STFL, void (*)(OQS_SIG_STFL*)> d_stflctx;
  std::string d_stflpubkey{""};
  pthread_mutex_t d_keylock;
  bool d_is_xmssmt;
};

bool LiboqsStflDNSCryptoKeyEngine::checkKey(std::optional<std::reference_wrapper<vector<string>>> errorMessages) const
{
  (void)errorMessages;
  return (d_stflprivkey && !d_stflpubkey.empty() && d_stflctx);
}

void LiboqsStflDNSCryptoKeyEngine::create(unsigned int oid)
{
  if (oid == 0 || (!d_is_xmssmt && oid > XMSS_SHAKE256_H20_oid) || (d_is_xmssmt && oid > XMSSMT_SHAKE128_H60_12_oid)) {
    throw runtime_error("oid: {" + std::to_string(oid) + "} is not support for " + getName());
  }
  std::string xmss_name;
  if (d_is_xmssmt)
    xmss_name = xmssmt_oid_to_oqsname(oid);
  else
    xmss_name = xmss_oid_to_oqsname(oid);
  auto ctx = std::unique_ptr<OQS_SIG_STFL, void (*)(OQS_SIG_STFL*)>(OQS_SIG_STFL_new(xmss_name.c_str()), OQS_SIG_STFL_free);
  if (!ctx) {
    throw runtime_error(getName() + " OQS_SIG_STFL initialisation failed");
  }
  auto priv_key = std::unique_ptr<OQS_SIG_STFL_SECRET_KEY, void (*)(OQS_SIG_STFL_SECRET_KEY*)>(OQS_SIG_STFL_SECRET_KEY_new(xmss_name.c_str()), OQS_SIG_STFL_SECRET_KEY_free);
  if (!priv_key) {
    throw runtime_error(getName() + " secret key generation failed");
  }
  std::string pub_key;
  pub_key.resize(ctx.get()->length_public_key);
  if (OQS_SIG_STFL_keypair(ctx.get(),
                           reinterpret_cast<unsigned char*>(&pub_key.at(0)),
                           priv_key.get())
      != OQS_SUCCESS) {
    throw runtime_error(getName() + " failed to generate public key");
  }
  OQS_SIG_STFL_SECRET_KEY_SET_lock(priv_key.get(), lock_sk);
  OQS_SIG_STFL_SECRET_KEY_SET_unlock(priv_key.get(), unlock_sk);
  if (pthread_mutex_init(&d_keylock, NULL) != 0) {
    throw runtime_error(getName() + " failed to initialize keylock");
  }
  OQS_SIG_STFL_SECRET_KEY_SET_mutex(priv_key.get(), &d_keylock);
  OQS_SIG_STFL_SECRET_KEY_SET_store_cb(priv_key.get(), save_sk, NULL);
  d_stflctx = std::move(ctx);
  d_stflprivkey = std::move(priv_key);
  d_stflpubkey = std::move(pub_key);
}

DNSCryptoKeyEngine::storvector_t LiboqsStflDNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvect;
  string algorithm;

  if (d_algorithm == DNSSECKeeper::XMSS) {
    algorithm = std::to_string(d_algorithm) + " (XMSS)";
  }
  else if (d_algorithm == DNSSECKeeper::XMSSMT) {
    algorithm = std::to_string(d_algorithm) + " (XMSSMT)";
  }
  else {
    algorithm = " ? (?)";
  }

  storvect.push_back(make_pair("Algorithm", algorithm));

  unsigned char* raw_key;
  size_t len = 0;

  if (OQS_SIG_STFL_SECRET_KEY_serialize(&raw_key, &len, d_stflprivkey.get()) != OQS_SUCCESS) {
    throw runtime_error(getName() + " failed to serialize private key");
  }
  if (raw_key == NULL || len != d_stflctx->length_secret_key) {
    throw runtime_error(getName() + " error serializing private key");
  }
  std::string buf(raw_key, raw_key + len);
  if (raw_key != NULL) {
    OQS_MEM_secure_free(raw_key, len);
  }
  storvect.push_back(std::make_pair("PrivateKey", buf));

  // Clear buffer and put public key into store vector
  buf.clear();

  storvect.push_back(std::make_pair("PublicKey", d_stflpubkey));

  return storvect;
}

std::string LiboqsStflDNSCryptoKeyEngine::sign(const std::string& message) const
{
  string msgToSign = message;

  size_t sig_len = d_stflctx.get()->length_signature;
  string signature;
  signature.resize(sig_len);

  if (OQS_SIG_STFL_sign(d_stflctx.get(),
                        reinterpret_cast<unsigned char*>(&signature.at(0)),
                        &sig_len,
                        reinterpret_cast<const unsigned char*>(&message.at(0)),
                        message.length(),
                        d_stflprivkey.get())
      != OQS_SUCCESS) {
    throw runtime_error(getName() + " signing error");
  }
  return signature;
}

bool LiboqsStflDNSCryptoKeyEngine::verify(const std::string& message, const std::string& signature) const
{
  string checkSignature = signature;
  string checkMsg = message;

  if (OQS_SIG_STFL_verify(d_stflctx.get(),
                          reinterpret_cast<unsigned char*>(&checkMsg.at(0)), checkMsg.length(),
                          reinterpret_cast<unsigned char*>(&checkSignature.at(0)), checkSignature.length(),
                          reinterpret_cast<const unsigned char*>(&d_stflpubkey.at(0)))
      != OQS_SUCCESS) {
    throw runtime_error(getName() + " verification failure");
  }

  return true;
}

std::string LiboqsStflDNSCryptoKeyEngine::getPublicKeyString() const
{
  if (d_stflpubkey == "") {
    throw runtime_error(getName() + " invalid public key pointer");
  }
  return d_stflpubkey;
}

void LiboqsStflDNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  drc.d_algorithm = atoi(stormap["algorithm"].c_str());
  if (drc.d_algorithm != d_algorithm) {
    throw runtime_error(getName() + " tried to feed an algorithm " + std::to_string(drc.d_algorithm) + " to a " + std::to_string(d_algorithm) + " key");
  }
  auto raw_private_key = stormap["privatekey"];
  auto pub_key = stormap["publickey"];

  unsigned int oid;
  if (d_is_xmssmt)
    oid = xmssmt_key_to_oid(pub_key);
  else
    oid = xmss_key_to_oid(pub_key);
  std::string xmss_name;
  if (d_is_xmssmt)
    xmss_name = xmssmt_oid_to_oqsname(oid);
  else
    xmss_name = xmss_oid_to_oqsname(oid);
  auto ctx = std::unique_ptr<OQS_SIG_STFL, void (*)(OQS_SIG_STFL*)>(OQS_SIG_STFL_new(xmss_name.c_str()), OQS_SIG_STFL_free);
  if (!ctx) {
    throw runtime_error(getName() + " failed to get stateful context");
  }
  auto priv_key = std::unique_ptr<OQS_SIG_STFL_SECRET_KEY, void (*)(OQS_SIG_STFL_SECRET_KEY*)>(OQS_SIG_STFL_SECRET_KEY_new(xmss_name.c_str()), OQS_SIG_STFL_SECRET_KEY_free);
  if (!priv_key) {
    throw runtime_error(getName() + " failed to initalize private key struct");
  }
  if (OQS_SIG_STFL_SECRET_KEY_deserialize(priv_key.get(),
                                          reinterpret_cast<unsigned char*>(&raw_private_key.at(0)),
                                          raw_private_key.length(),
                                          nullptr)
      != OQS_SUCCESS) {
    throw runtime_error(getName() + " failed to deserialize key");
  }
  OQS_SIG_STFL_SECRET_KEY_SET_lock(priv_key.get(), lock_sk);
  OQS_SIG_STFL_SECRET_KEY_SET_unlock(priv_key.get(), unlock_sk);
  if (pthread_mutex_init(&d_keylock, NULL) != 0) {
    throw runtime_error(getName() + " failed to initalize keylock");
  }
  OQS_SIG_STFL_SECRET_KEY_SET_mutex(priv_key.get(), &d_keylock);
  OQS_SIG_STFL_SECRET_KEY_SET_store_cb(priv_key.get(), save_sk, NULL);
  d_stflctx = std::move(ctx);
  d_stflprivkey = std::move(priv_key);
  d_stflpubkey = std::move(pub_key);
}

void LiboqsStflDNSCryptoKeyEngine::fromPublicKeyString(const std::string& content)
{
  unsigned int oid;
  if (d_is_xmssmt)
    oid = xmssmt_key_to_oid(content);
  else
    oid = xmss_key_to_oid(content);
  std::string xmss_name;
  if (d_is_xmssmt)
    xmss_name = xmssmt_oid_to_oqsname(oid);
  else
    xmss_name = xmss_oid_to_oqsname(oid);
  auto ctx = std::unique_ptr<OQS_SIG_STFL, void (*)(OQS_SIG_STFL*)>(OQS_SIG_STFL_new(xmss_name.c_str()), OQS_SIG_STFL_free);
  if (!ctx) {
    throw runtime_error(getName() + " failed to get stateful context");
  }
  if (content.length() != ctx.get()->length_public_key) {
    throw runtime_error(getName() + " wrong public key length for algorithm " + std::to_string(d_algorithm));
  }
  d_stflctx = std::move(ctx);
  d_stflpubkey = std::move(content);
}
#endif

namespace
{
const struct LoaderStruct
{
  LoaderStruct()
  {
#ifdef HAVE_LIBCRYPTO_PQC
    DNSCryptoKeyEngine::report(DNSSECKeeper::XMSS, &LiboqsStflDNSCryptoKeyEngine::maker);
    DNSCryptoKeyEngine::report(DNSSECKeeper::XMSSMT, &LiboqsStflDNSCryptoKeyEngine::maker);
#endif
  }
} loaderLiboqs;
}
