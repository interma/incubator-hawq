/********************************************************************
 * 2014 -
 * open source under Apache License Version 2.0
 ********************************************************************/
/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <algorithm>
#include <cctype>

#include "Exception.h"
#include "ExceptionInternal.h"
#include "SaslClient.h"
#include <curl/curl.h>
#include <string>
#include <sstream>
#include <map>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using boost::property_tree::ptree;
using boost::property_tree::read_json;
using boost::property_tree::write_json;

#define SASL_SUCCESS 0

namespace Hdfs {
namespace Internal {

//todo @interma
std::string calculateIV(std::string initIV, long counter) {
    std::string IV;
    IV.resize(initIV.length());
    int i = initIV.length();
    int j = 0;
    int sum = 0;
    unsigned c;
    while (i-- > 0) {
      // (sum >>> Byte.SIZE) is the carry for addition
      sum = (((unsigned char)initIV.c_str()[i]) & 0xff) + ((unsigned int)sum >> 8);
      if (j++ < 8) { // Big-endian, and long is 8 bytes length
        sum += (unsigned char) counter & 0xff;
        c = (unsigned long) counter;
        c >>= (unsigned)8;
        counter = c;
      }
      IV[i] = (unsigned char) sum;
    }
    return IV;
}

void printArray(std::string str, const char* text) {
    int i=0;
    printf("length %d: %s\n", (int)str.length(), text);
    for (i=0; i < (int)str.length(); i++) {
        printf("%02d ", (int)str[i]);
    }
    printf("\n");

}
bool AESClient::initialized = false;

AESClient::AESClient(std::string enckey, std::string enciv,
              std::string deckey, std::string deciv, int bufsize) :
              encrypt(NULL), decrypt(NULL), packetsSent(0), decoffset(0), bufsize(bufsize),
              enckey(enckey), enciv(enciv), deckey(deckey), deciv(deciv), initdeciv(deciv)
{
    if (!initialized) {
      ERR_load_crypto_strings();
      OpenSSL_add_all_algorithms();
      OPENSSL_config(NULL);
      initialized = true;
    }
    encrypt = NULL;
    decrypt = NULL;
    encrypt = EVP_CIPHER_CTX_new();
    if (!encrypt) {
        std::string err = ERR_lib_error_string(ERR_get_error());
        THROW(HdfsIOException, "Cannot initialize aes encrypt context %s",
              err.c_str());
    }
    decrypt = EVP_CIPHER_CTX_new();
    if (!decrypt) {
        std::string err = ERR_lib_error_string(ERR_get_error());
        THROW(HdfsIOException, "Cannot initialize aes decrypt context %s",
              err.c_str());
    }
    std::string iv = enciv;
    const EVP_CIPHER *cipher = NULL;
    if (enckey.length() == 32)
        cipher = EVP_aes_256_ctr();
    else if (enckey.length() == 16)
        cipher = EVP_aes_128_ctr();
    else
        cipher = EVP_aes_192_ctr();
    if (!EVP_CipherInit_ex(encrypt, cipher, NULL,
        (const unsigned char*)enckey.c_str(), (const unsigned char*)iv.c_str(), 1)) {
        std::string err = ERR_lib_error_string(ERR_get_error());
        THROW(HdfsIOException, "Cannot initialize aes encrypt cipher %s",
              err.c_str());
    }
    iv = deciv;
    if (!EVP_CipherInit_ex(decrypt, cipher, NULL, (const unsigned char*)deckey.c_str(),
        (const unsigned char*)iv.c_str(), 0)) {
        std::string err = ERR_lib_error_string(ERR_get_error());
        THROW(HdfsIOException, "Cannot initialize aes decrypt cipher %s",
              err.c_str());
    }
    EVP_CIPHER_CTX_set_padding(encrypt, 0);
    EVP_CIPHER_CTX_set_padding(decrypt, 0);

}

AESClient::~AESClient() {
    if (encrypt)
        EVP_CIPHER_CTX_free(encrypt);
    if (decrypt)
        EVP_CIPHER_CTX_free(decrypt);
}

std::string AESClient::encode(const char *input, size_t input_len) {
    int len;
    std::string result;
    result.resize(input_len);
    int offset = 0;
    int remaining = input_len;

    while (remaining > bufsize) {
        if (!EVP_CipherUpdate (encrypt, (unsigned char*)&result[offset], &len, (const unsigned char*)input+offset, bufsize)) {
            std::string err = ERR_lib_error_string(ERR_get_error());
            THROW(HdfsIOException, "Cannot encrypt AES data %s",
                  err.c_str());
        }
        offset += len;
        remaining -= len;
    }
    if (remaining) {

        if (!EVP_CipherUpdate (encrypt, (unsigned char*)&result[offset], &len, (const unsigned char*)input+offset, remaining)) {
            std::string err = ERR_lib_error_string(ERR_get_error());
            THROW(HdfsIOException, "Cannot encrypt AES data %s",
                  err.c_str());
        }
    }
    return result;
}


std::string AESClient::decode(const char *input, size_t input_len) {
    int len;
    std::string result;
    result.resize(input_len);
    int offset = 0;
    int remaining = input_len;

    while (remaining > bufsize) {
        if (!EVP_CipherUpdate (decrypt, (unsigned char*)&result[offset], &len, (const unsigned char*)input+offset, bufsize)) {
            std::string err = ERR_lib_error_string(ERR_get_error());
            THROW(HdfsIOException, "Cannot decrypt AES data %s",
                  err.c_str());
        }
        offset += len;
        remaining -= len;
    }
    if (remaining) {

        if (!EVP_CipherUpdate (decrypt, (unsigned char*)&result[offset], &len, (const unsigned char*)input+offset, remaining)) {
            std::string err = ERR_lib_error_string(ERR_get_error());
            THROW(HdfsIOException, "Cannot decrypt AES data %s",
                  err.c_str());
        }
    }
    decoffset += input_len;
    return result;

}




SaslClient::SaslClient(const RpcSaslProto_SaslAuth & auth, const Token & token,
                       const std::string & principal, bool encryptedData) :
     aes(NULL), ctx(NULL), session(NULL), changeLength(false), complete(false),
     privacy(false), integrity(false),
     theAuth(auth), theToken(token), thePrincipal(principal), encryptedData(encryptedData)   {
    int rc;
    ctx = NULL;
    RpcAuth method = RpcAuth(RpcAuth::ParseMethod(auth.method()));
    rc = gsasl_init(&ctx);

    if (rc != GSASL_OK) {
        THROW(HdfsIOException, "cannot initialize libgsasl");
    }

    switch (method.getMethod()) {
    case AuthMethod::KERBEROS:
        initKerberos(auth, principal);
        break;

    case AuthMethod::TOKEN:
        initDigestMd5(auth, token);
        break;

    default:
        THROW(HdfsIOException, "unknown auth method.");
        break;
    }
}

SaslClient::~SaslClient() {
    if (aes)
        delete aes;

    if (session != NULL) {
        gsasl_finish(session);
        session = NULL;
    }

    if (ctx != NULL) {
        gsasl_done(ctx);
        ctx = NULL;
    }
}

bool SaslClient::needsLength() {
    if (aes != NULL)
        return false;
    if ((!privacy && !integrity) || (!complete))
        return false;
    return true;
}

void SaslClient::setAes(AESClient *client) {
    aes = client;
}

void SaslClient::initKerberos(const RpcSaslProto_SaslAuth & auth,
                              const std::string & principal) {
    int rc;

    /* Create new authentication session. */
    if ((rc = gsasl_client_start(ctx, auth.mechanism().c_str(), &session)) != GSASL_OK) {
        THROW(HdfsIOException, "Cannot initialize client (%d): %s", rc,
              gsasl_strerror(rc));
    }

    gsasl_property_set(session, GSASL_SERVICE, auth.protocol().c_str());
    gsasl_property_set(session, GSASL_AUTHID, principal.c_str());
    gsasl_property_set(session, GSASL_HOSTNAME, auth.serverid().c_str());

}

std::string Base64Encode(const std::string & in) {
    char * temp;
    size_t len;
    std::string retval;
    int rc = gsasl_base64_to(in.c_str(), in.size(), &temp, &len);

    if (rc != GSASL_OK) {
        if (rc == GSASL_BASE64_ERROR)
            THROW(HdfsIOException, "SaslClient: Failed to encode string to base64");
        throw std::bad_alloc();
    }

    if (temp) {
        retval = temp;
        free(temp);
    }

    if (!temp || retval.length() != len) {
        THROW(HdfsIOException, "SaslClient: Failed to encode string to base64");
    }

    return retval;
}

std::string Base64Decode(const std::string & in) {
    char * temp;
    size_t len;
    std::string retval;
    int rc = gsasl_base64_from(in.c_str(), in.size(), &temp, &len);

    if (rc != GSASL_OK) {
        if (rc == GSASL_BASE64_ERROR)
            THROW(HdfsIOException, "SaslClient: Failed to decode string to base64");
        throw std::bad_alloc();
    }

    if (temp) {
        retval.assign(temp, len);
        free(temp);
    }

    if (!temp || retval.length() != len) {
        THROW(HdfsIOException, "SaslClient: Failed to decode string to base64");
    }

    return retval;
}

void SaslClient::initDigestMd5(const RpcSaslProto_SaslAuth & auth,
                               const Token & token) {
    int rc;

    if ((rc = gsasl_client_start(ctx, auth.mechanism().c_str(), &session)) != GSASL_OK) {
        THROW(HdfsIOException, "Cannot initialize client (%d): %s", rc, gsasl_strerror(rc));
    }

    std::string password = Base64Encode(token.getPassword());
    std::string identifier;

    if (!encryptedData)
        identifier = Base64Encode(token.getIdentifier());
    else
        identifier = token.getIdentifier();
    gsasl_property_set(session, GSASL_PASSWORD, password.c_str());
    gsasl_property_set_raw(session, GSASL_AUTHID, identifier.c_str(), identifier.length());
    gsasl_property_set(session, GSASL_HOSTNAME, auth.serverid().c_str());
    gsasl_property_set(session, GSASL_SERVICE, auth.protocol().c_str());
    changeLength = true;

}

int SaslClient::findPreferred(int possible) {
    if (possible & GSASL_QOP_AUTH)
        return GSASL_QOP_AUTH;
    if (possible & GSASL_QOP_AUTH_INT)
        return GSASL_QOP_AUTH_INT;
    if (possible & GSASL_QOP_AUTH_CONF)
        return GSASL_QOP_AUTH_CONF;
    return GSASL_QOP_AUTH;
}


std::string SaslClient::evaluateChallenge(const std::string & challenge) {
    int rc;
    char * output = NULL;
    size_t outputSize;
    std::string retval;
    rc = gsasl_step(session, &challenge[0], challenge.size(), &output,
                    &outputSize);
    RpcAuth method = RpcAuth(RpcAuth::ParseMethod(theAuth.method()));
    if (rc == GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR && method.getMethod() == AuthMethod::KERBEROS) {
        // Try again using principal instead
        gsasl_finish(session);
        initKerberos(theAuth, thePrincipal);
        gsasl_property_set(session, GSASL_GSSAPI_DISPLAY_NAME, thePrincipal.c_str());
        rc = gsasl_step(session, &challenge[0], challenge.size(), &output,
                    &outputSize);
    }

    if (rc == GSASL_NEEDS_MORE || rc == GSASL_OK) {
        retval.resize(outputSize);
        memcpy(&retval[0], output, outputSize);

        if (output) {
            free(output);
        }
    } else {
        if (output) {
            free(output);
        }

        THROW(AccessControlException, "Failed to evaluate challenge: %s", gsasl_strerror(rc));
    }

    if (rc == GSASL_OK) {
        complete = true;
        int preferred = 0;
        if (method.getMethod() == AuthMethod::TOKEN) {
            const char *qop = gsasl_property_get (session, GSASL_QOP);
            if (qop)
                preferred = qop[0];
        }
        else if (challenge.length()) {
            std::string decoded = decode(challenge.c_str(), challenge.length());
            int qop = (int)decoded.c_str()[0];
            preferred = findPreferred(qop);
        }
        if (preferred & GSASL_QOP_AUTH_CONF) {
            privacy = true;
            integrity = true;
        } else if (preferred & GSASL_QOP_AUTH_INT) {
            integrity = true;
        }
    }

    return retval;
}

std::string SaslClient::encode(const char *input, size_t input_len) {
    std::string result;
    if ((!privacy && !integrity) || (!complete)) {
        result.resize(input_len);
        memcpy(&result[0], input, input_len);
        return result;
    }
    if (aes)
        return aes->encode(input, input_len);

    char *output=NULL;
    size_t output_len;
    int rc = gsasl_encode(session, input, input_len, &output, &output_len);
    if (rc != GSASL_OK) {
        THROW(AccessControlException, "Failed to encode wrapped data: %s", gsasl_strerror(rc));
    }
    if (output_len) {

        if (output_len > 4 && changeLength) {
            result.resize(output_len-4);
            memcpy(&result[0], output+4, output_len-4);
        } else {
            result.resize(output_len);
            memcpy(&result[0], output, output_len);
        }
        free(output);
    }
    return result;
}


std::string  SaslClient::decode(const char *input, size_t input_len) {
    std::string result;
    if ((!privacy && !integrity) || (!complete)) {
        result.resize(input_len);
        memcpy(&result[0], input, input_len);
        return result;
    }
    if (aes)
        return aes->decode(input, input_len);

    char *output=NULL;
    size_t output_len;
    std::string actualInput;
    if (changeLength) {
        actualInput.resize(input_len+4);
        actualInput[0] = (input_len>> 24) & 0xFF;
        actualInput[1] = (input_len >> 16) & 0xFF;
        actualInput[2] = (input_len >> 8) & 0xFF;
        actualInput[3] = input_len & 0xFF;
        memcpy(&actualInput[4], input, input_len);

    } else {
        actualInput.resize(input_len);
        memcpy(&actualInput[0], input, input_len);
    }
    int rc = gsasl_decode(session, actualInput.c_str(), actualInput.length(), &output, &output_len);
    if (rc != GSASL_OK) {
        THROW(AccessControlException, "Failed to decode wrapped data: %s", gsasl_strerror(rc));
    }
    if (output_len) {
        result.resize(output_len);
        memcpy(&result[0], output, output_len);
        free(output);
    }

    return result;
}


bool SaslClient::isComplete() {
    return complete;
}

bool SaslClient::isPrivate() {
    return privacy;
}

bool SaslClient::isIntegrity() {
    return integrity;
}



class BodyOutput {
public:
    void append(void *data, size_t size) {
        output.append((const char*)data, size);
    }

    void reset() {
        output = "";
    }

    ptree fromJson() {
        ptree pt2;
        std::istringstream is (output);
        try {
            read_json (is, pt2);
            return pt2;
        } catch (const boost::exception & e)
        {
            THROW(HdfsIOException, "Error parsing KMS data as JSON");
        }
    }
    std::string toJson(ptree &data) {
        std::ostringstream buf;
        try {
            write_json (buf, data, false);
            std::string json = buf.str();
            return json;
        } catch (const boost::exception & e)
        {
            THROW(HdfsIOException, "Error converting KMS data to JSON");
        }
    }
private:
    std::string output;
};

class HeaderOutput {
public:
    void append(char *data, size_t size) {
        char *ptr = (char*) memchr(data, ':', size);
        if (ptr) {
            int idx = ptr-data;
            std::string key;
            key.assign(data, idx);
            std::string value;
            int offset = 1;
            if (*(ptr+1) == ' ')
                offset += 1;
            value.assign(ptr+offset, size-idx-offset);

            size_t last = value.find_last_not_of("\r\n");
            if (last == value.npos)
                value = "";
            else
                value =  value.substr(0, (last+1));

            headers[key] = value;

            if (key == "Set-Cookie") {
                std::string auth_cookie = "hadoop.auth";
                std::string auth_cookie_eq = auth_cookie + "=";
                int pos = value.find(auth_cookie_eq);
                if (pos != (int)value.npos) {
                    std::string token = value.substr(pos+auth_cookie_eq.length());
                    int separator = token.find(";");
                    if (separator != (int)token.npos) {
                        token = token.substr(0, separator);
                    }
                    kmsToken = token;
                }
            }
        }
    }

    std::string& getKmsToken() {
        return kmsToken;
    }

    std::string& getValue(const char* key) {
         try {
            return headers.at(key);
         } catch (std::out_of_range & oor) {
            THROW(HdfsIOException, "Cannot find key in HTTP headers for KMS: %s", key);
         }
    }

    void reset() {
        headers.clear();
    }

private:
    std::map<std::string, std::string> headers;
    std::string kmsToken;
};

std::string parse_url(std::string data) {
    std::string start = "kms://";
    std::string http = "http@";
    std::string https = "https@";
    if (data.compare(0, start.length(), start) == 0) {
        start = data.substr(start.length());
        if (start.compare(0, http.length(), http) == 0) {
            return "http://" + start.substr(http.length());
        }
        else if (start.compare(0, https.length(), https) == 0) {
            return "https://" + start.substr(https.length());
        }
        else
            THROW(HdfsIOException, "Bad KMS provider URL: %s", data.c_str());
    }
    else
        THROW(HdfsIOException, "Bad KMS provider URL: %s", data.c_str());

}

#define CURL_SETOPT(handle, option, optarg, fmt, ...) \
    res = curl_easy_setopt(handle, option, optarg); \
    if (res != CURLE_OK) { \
        THROW(HdfsIOException, fmt, ##__VA_ARGS__); \
    }

#define CURL_SETOPT_ERROR1(handle, option, optarg, fmt) \
    CURL_SETOPT(handle, option, optarg, fmt, curl_easy_strerror(res));

#define CURL_SETOPT_ERROR2(handle, option, optarg, fmt) \
    CURL_SETOPT(handle, option, optarg, fmt, curl_easy_strerror(res), \
        errorString().c_str())

#define CURL_PERFORM(handle, fmt) \
    res = curl_easy_perform(handle); \
    if (res != CURLE_OK) { \
        THROW(HdfsIOException, fmt, curl_easy_strerror(res), errorString().c_str()); \
    }


#define CURL_GETOPT_ERROR2(handle, option, optarg, fmt) \
    res = curl_easy_getinfo(handle, option, optarg); \
    if (res != CURLE_OK) { \
        THROW(HdfsIOException, fmt, curl_easy_strerror(res), errorString().c_str()); \
    }

#define CURL_GET_RESPONSE(handle, code, fmt) \
    CURL_GETOPT_ERROR2(handle, CURLINFO_RESPONSE_CODE, code, fmt);

class GetDecryptedKeyImpl : public GetDecryptedKey {
public:
    GetDecryptedKeyImpl(std::string url, RpcAuth & auth): handle(NULL), list(NULL), url(parse_url(url)),
     auth(auth), ctx(NULL), session(NULL) {
        if (!initialized) {
            initialized = true;
            CURLcode ret = curl_global_init(CURL_GLOBAL_ALL);
            if (ret) {
                 THROW(HdfsIOException, "Cannot initialize curl client for KMS");
            }
        }
        handle = curl_easy_init();
        if (!handle)
            THROW(HdfsIOException, "Cannot initialize curl handle for KMS");

        CURLcode res;
        CURL_SETOPT_ERROR1(handle, CURLOPT_ERRORBUFFER, errbuf,
            "Cannot initialize curl error buffer for KMS: %s");

        errbuf[0] = 0;
        CURL_SETOPT_ERROR2(handle, CURLOPT_SSL_VERIFYPEER, 0,
            "Cannot initialize SSL no verify for KMS: %s: %s");

        CURL_SETOPT_ERROR2(handle, CURLOPT_NOPROGRESS, 1,
            "Cannot initialize no progress for KMS: %s: %s");

        CURL_SETOPT_ERROR2(handle, CURLOPT_VERBOSE, 0,
            "Cannot initialize no verbose for KMS: %s: %s");

        CURL_SETOPT_ERROR2(handle, CURLOPT_COOKIEFILE, "",
            "Cannot initialize cookie behavior for KMS: %s: %s");

        addHeader("Content-Type: application/json");
        addHeader("Accept: *");

        CURL_SETOPT_ERROR2(handle, CURLOPT_HTTPHEADER, list,
            "Cannot initialize headers for KMS: %s: %s");

        CURL_SETOPT_ERROR2(handle, CURLOPT_WRITEFUNCTION, CurlWriteMemoryCallback,
            "Cannot initialize body reader for KMS: %s: %s");

        CURL_SETOPT_ERROR2(handle, CURLOPT_WRITEDATA, (void *)&output,
            "Cannot initialize body reader data for KMS: %s: %s");

        /* some servers don't like requests that are made without a user-agent
            field, so we provide one */
        CURL_SETOPT_ERROR2(handle, CURLOPT_USERAGENT, "libcurl-agent/1.0",
            "Cannot initialize user agent for KMS: %s: %s");

        method = auth.getMethod();
        if (method == AuthMethod::KERBEROS) {
            initKerberos();
        }
    }

    void addHeader(const char* headervalue) {
        list = curl_slist_append(list, headervalue);
        if (!list) {
            THROW(HdfsIOException, "Cannot add header for KMS");
        }
    }

    void initKerberos() {
        int rc = gsasl_init(&ctx);

        if (rc != GSASL_OK) {
            THROW(HdfsIOException, "cannot initialize libgsasl");
        }
        /* Create new authentication session. */
        if ((rc = gsasl_client_start(ctx, "GSSAPI", &session)) != GSASL_OK) {
            THROW(HdfsIOException, "Cannot initialize client (%d): %s", rc,
                  gsasl_strerror(rc));
        }
        std::string principal = auth.getUser().getPrincipal();
        gsasl_property_set(session, GSASL_AUTHID, principal.c_str());

        std::string http = "http://";
        std::string https = "https://";
        std::string host = "";

        if (url.compare(0, http.length(), http) == 0)
            host = url.substr(http.length());
        else
            host = url.substr(https.length());
        size_t pos = host.find(":");
        if (pos != host.npos) {
            host = host.substr(0, pos);
        }
        gsasl_property_set(session, GSASL_HOSTNAME, host.c_str());

        spn = "HTTP";
        gsasl_property_set(session, GSASL_SERVICE, spn.c_str());
}

    ~GetDecryptedKeyImpl() {
        if (list)
            curl_slist_free_all(list);
        if (handle)
            curl_easy_cleanup(handle);

        if (session != NULL) {
            gsasl_finish(session);
            session = NULL;
        }

        if (ctx != NULL) {
            gsasl_done(ctx);
            ctx = NULL;
        }

    }
    std::string errorString() {
        if (strlen(errbuf) == 0)
            return "";
        return errbuf;
    }

    static size_t
    CurlWriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    {
      size_t realsize = size * nmemb;
      BodyOutput *mem = (BodyOutput*)userp;

      mem->append(contents, realsize);
      return realsize;
    }

    static size_t
    CurlWriteHeaderCallback(char *contents, size_t size, size_t nmemb, void *userp)
    {
      size_t realsize = size * nmemb;
      HeaderOutput *mem = (HeaderOutput*)userp;

      mem->append(contents, realsize);
      return realsize;
    }

    std::string escape(std::string value) {
        char *output = curl_easy_escape(handle, value.c_str(), value.length());
        if(output) {
            std::string ret = output;
            curl_free(output);
            return ret;
        } else {
            THROW(HdfsIOException, "Cannot convert URL to escaped version for KMS: %s", value.c_str());
        }
    }
    std::string build_url(std::string name, bool tokenOnly) {

        std::string base = url;
        if (tokenOnly)
            base = url + "/v1/?op=GETDELEGATIONTOKEN";
        else {
            base = url + "/v1/keyversion/" + escape(name);
            base = base + "/_eek?eek_op=decrypt";
        }

        if (method == AuthMethod::KERBEROS) {
            return base;
        } else if (method == AuthMethod::SIMPLE) {
            std::string user = auth.getUser().getRealUser();
            if (user.length() == 0)
                user = auth.getUser().getKrbName();
            return base + "&user.name=" + user;

        }
        else {
            return base;
        }

    }

    std::string getMaterial(FileEncryption& encryption,  bool tokenOnly = false) {
        CURLcode res;
        std:: string curl = build_url(encryption.getEzKeyVersionName(), tokenOnly);

        CURL_SETOPT_ERROR2(handle, CURLOPT_URL, curl.c_str(),
            "Cannot initialize url for KMS: %s: %s");

        if (tokenOnly) {
            CURL_SETOPT_ERROR2(handle, CURLOPT_POST, 0,
                "Cannot initialize post for KMS: %s: %s");
        } else {
            CURL_SETOPT_ERROR2(handle, CURLOPT_POST, 1,
                "Cannot initialize post for KMS: %s: %s");
        }

        ptree map;
        long response_code;
        map.put("iv", Base64Encode(encryption.getIv()));
        map.put("name", encryption.getKeyName());
        map.put("material", Base64Encode(encryption.getKey()));
        std::string data = output.toJson(map);

        if (!tokenOnly) {
            CURL_SETOPT_ERROR2(handle, CURLOPT_COPYPOSTFIELDS, data.c_str(),
                "Cannot initialize post data for KMS: %s: %s");
        }

        if (method == AuthMethod::KERBEROS) {
            int rc;
            char * outputStr = NULL;
            size_t outputSize;
            std::string retval;
            std::string challenge = "";
            rc = gsasl_step(session, &challenge[0], challenge.size(), &outputStr,
                            &outputSize);
            if (rc == GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR && method == AuthMethod::KERBEROS) {
                // Try again using principal instead
                gsasl_finish(session);
                initKerberos();
                gsasl_property_set(session, GSASL_GSSAPI_DISPLAY_NAME, auth.getUser().getPrincipal().c_str());
                rc = gsasl_step(session, &challenge[0], challenge.size(), &outputStr,
                            &outputSize);
            }
            if (rc != GSASL_OK && rc != GSASL_NEEDS_MORE)
                THROW(AccessControlException, "Failed to negotiate with KMS: %s", gsasl_strerror(rc));

            retval.resize(outputSize);
            memcpy(&retval[0], outputStr, outputSize);

            if (outputStr) {
                free(outputStr);
            }
            std::string temp;
            std::string encoded = Base64Encode(retval);
            std::replace(encoded.begin(), encoded.end(), '+', '-');
            std::replace(encoded.begin(), encoded.end(), '/', '_');
            temp = "Authorization: Negotiate " + encoded;
            addHeader(temp.c_str());

            CURL_SETOPT_ERROR2(handle, CURLOPT_HEADERFUNCTION, CurlWriteHeaderCallback,
                "Cannot initialize header reader for KMS: %s: %s");

            CURL_SETOPT_ERROR2(handle, CURLOPT_HEADERDATA, (void *)&header,
                "Cannot initialize header reader data for KMS: %s: %s");

            CURL_SETOPT_ERROR2(handle, CURLOPT_HTTPHEADER, list,
                "Cannot initialize headers for KMS: %s: %s");

            CURL_PERFORM(handle, "Could not send request to KMS: %s %s");

            if (tokenOnly) {
                CURL_GET_RESPONSE(handle, &response_code,
                "Cannot get response code for KMS: %s: %s");

                if (response_code != 200) {
                    THROW(HdfsIOException, "KMS Token not gotten: %ld", response_code);
                }
                map = output.fromJson();

                try {
                    token = map.get<std::string> ("Token.urlString");
                } catch (const boost::exception & e)
                {
                    THROW(HdfsIOException, "Error converting KMS response to token");
                }
                return token;
            }

        } else if (method == AuthMethod::SIMPLE) {
            // Once to get cookie for simple auth.
            CURL_PERFORM(handle, "Could not send request to KMS: %s %s");

            CURL_GET_RESPONSE(handle, &response_code,
                "Cannot get response code for KMS: %s: %s");

            if (response_code != 200) {
                output.reset();
                CURL_PERFORM(handle, "Could not send request to KMS: %s %s");
            }
        } else {

            const Token *ptr = auth.getUser().selectToken("kms-dt", "kms");
            if (!ptr)
                THROW(HdfsIOException, "Can't find provided KMS token");
            std::string auth_cookie = "hadoop.auth";
            std::string auth_cookie_eq = auth_cookie + "=";
            std::string kmsToken = ptr->getIdentifier();

            if (kmsToken.length() == 0)
                 THROW(HdfsIOException, "KMS Token not set");

            std::string temp = "X-Hadoop-Delegation-Token: " + kmsToken;
            addHeader(temp.c_str());
            CURL_PERFORM(handle, "Could not send request to KMS: %s %s");

            CURL_GET_RESPONSE(handle, &response_code,
                "Cannot get response code for KMS: %s: %s");

            if (response_code != 200) {
                output.reset();
                CURL_PERFORM(handle, "Could not send request to KMS: %s %s");
            }
        }
        CURL_GET_RESPONSE(handle, &response_code,
                "Cannot get response code for KMS: %s: %s");

        if (response_code != 200)
            THROW(HdfsIOException, "Got invalid response from KMS: %d", (int)response_code);

        map = output.fromJson();

        try {
            data = map.get<std::string> ("material");
        } catch (const boost::exception & e)
        {
            THROW(HdfsIOException, "Error converting KMS response to decrypted key");
        }
        int rem = data.length() % 4;
        if (rem) {
            rem = 4 - rem;
            while (rem != 0 ) {
                data = data + "=";
                rem -= 1;
            }
        }
        std::replace(data.begin(), data.end(), '-', '+');
        std::replace(data.begin(), data.end(), '_', '/');
        return Base64Decode(data);
    }

private:
    static bool initialized;
    CURL *handle;
    struct curl_slist *list;
    char errbuf[CURL_ERROR_SIZE];
    BodyOutput output;
    HeaderOutput header;
    std::string url;
    RpcAuth &auth;
    AuthMethod method;
    Gsasl * ctx;
    Gsasl_session * session;
    std::string spn;
    std::string token;

};

bool GetDecryptedKeyImpl::initialized = false;

GetDecryptedKey* GetDecryptedKey::getDecryptor(std::string url, RpcAuth & auth) {
    return new GetDecryptedKeyImpl(url, auth);
}
}
}

