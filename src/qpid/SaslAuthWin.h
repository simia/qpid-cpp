#ifndef QPID_SSPISASLSERVER_H
#define QPID_SSPISASLSERVER_H

/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
#include "qpid/CommonImportExport.h"
#include "qpid/SaslServer.h"
#include <windows.h>
#include <sddl.h>
#define SECURITY_WIN32
#include <Security.h>

namespace qpid {

    /**
     * Dummy implementation of the SASL server role. This will advertise
     * ANONYMOUS and PLAIN, and parse the reponse data for those
     * accordingly, but will make no attempt to actually authenticate
     * users.
     */
    class SspiSaslServer : public SaslServer
    {
    public:
        QPID_COMMON_EXTERN SspiSaslServer(const std::string& realm);
        Status start(const std::string& mechanism, const std::string* response, std::string& challenge);
        Status step(const std::string* response, std::string& challenge);
        std::string getMechanisms();
        std::string getUserid();
        std::auto_ptr<qpid::sys::SecurityLayer> getSecurityLayer(size_t);
    private:
        std::string realm;
        std::string userid;
        HANDLE userToken;

        void acceptContext(const std::string*);

        SECURITY_STATUS maj_stat;
        CredHandle cred;
        TimeStamp cred_expiry;
        CtxtHandle context;

        SecBufferDesc send_tok_desc;
        SecBuffer     send_tok;
        SecBufferDesc recv_tok_desc;
        SecBuffer     recv_tok;
        SecPkgContext_Sizes context_sizes;

        void checkStatus()
        {
            switch (maj_stat) {
#define ZMQ_MACRO(id) case SEC_E_##id:  printf (#id ## "\n"); break; 
                    ZMQ_MACRO(INSUFFICIENT_MEMORY)
                    ZMQ_MACRO(INVALID_HANDLE)
                    ZMQ_MACRO(UNSUPPORTED_FUNCTION)
                    ZMQ_MACRO(TARGET_UNKNOWN)
                    ZMQ_MACRO(INTERNAL_ERROR)
                    ZMQ_MACRO(SECPKG_NOT_FOUND)
                    ZMQ_MACRO(NOT_OWNER)
                    ZMQ_MACRO(CANNOT_INSTALL)
                    ZMQ_MACRO(INVALID_TOKEN)
                    ZMQ_MACRO(CANNOT_PACK)
                    ZMQ_MACRO(QOP_NOT_SUPPORTED)
                    ZMQ_MACRO(NO_IMPERSONATION)
                    ZMQ_MACRO(LOGON_DENIED)
                    ZMQ_MACRO(UNKNOWN_CREDENTIALS)
                    ZMQ_MACRO(NO_CREDENTIALS)
                    ZMQ_MACRO(INCOMPLETE_MESSAGE)
                    ZMQ_MACRO(OUT_OF_SEQUENCE)
                    ZMQ_MACRO(MESSAGE_ALTERED)
                    ZMQ_MACRO(NO_AUTHENTICATING_AUTHORITY)
                    ZMQ_MACRO(BAD_PKGID)
                    ZMQ_MACRO(CONTEXT_EXPIRED)
                    ZMQ_MACRO(INCOMPLETE_CREDENTIALS)
                    ZMQ_MACRO(BUFFER_TOO_SMALL)
                    ZMQ_MACRO(WRONG_PRINCIPAL)
                    ZMQ_MACRO(TIME_SKEW)
                    ZMQ_MACRO(UNTRUSTED_ROOT)
                    ZMQ_MACRO(ILLEGAL_MESSAGE)
                    ZMQ_MACRO(CERT_UNKNOWN)
                    ZMQ_MACRO(CERT_EXPIRED)
                    ZMQ_MACRO(ENCRYPT_FAILURE)
                    ZMQ_MACRO(DECRYPT_FAILURE)
                    ZMQ_MACRO(ALGORITHM_MISMATCH)
                    ZMQ_MACRO(SECURITY_QOS_FAILED)
                    ZMQ_MACRO(UNFINISHED_CONTEXT_DELETED)
                    ZMQ_MACRO(NO_TGT_REPLY)
                    ZMQ_MACRO(NO_IP_ADDRESSES)
                    ZMQ_MACRO(WRONG_CREDENTIAL_HANDLE)
                    ZMQ_MACRO(CRYPTO_SYSTEM_INVALID)
                    ZMQ_MACRO(MAX_REFERRALS_EXCEEDED)
                    ZMQ_MACRO(MUST_BE_KDC)
                    ZMQ_MACRO(STRONG_CRYPTO_NOT_SUPPORTED)
                    ZMQ_MACRO(TOO_MANY_PRINCIPALS)
                    ZMQ_MACRO(NO_PA_DATA)
                    ZMQ_MACRO(PKINIT_NAME_MISMATCH)
                    ZMQ_MACRO(SMARTCARD_LOGON_REQUIRED)
                    ZMQ_MACRO(SHUTDOWN_IN_PROGRESS)
                    ZMQ_MACRO(KDC_INVALID_REQUEST)
                    ZMQ_MACRO(KDC_UNABLE_TO_REFER)
                    ZMQ_MACRO(KDC_UNKNOWN_ETYPE)
                    ZMQ_MACRO(UNSUPPORTED_PREAUTH)
                    ZMQ_MACRO(DELEGATION_REQUIRED)
                    ZMQ_MACRO(BAD_BINDINGS)
                    ZMQ_MACRO(MULTIPLE_ACCOUNTS)
                    ZMQ_MACRO(NO_KERB_KEY)
                    ZMQ_MACRO(CERT_WRONG_USAGE)
                    ZMQ_MACRO(DOWNGRADE_DETECTED)
                    ZMQ_MACRO(SMARTCARD_CERT_REVOKED)
                    ZMQ_MACRO(ISSUING_CA_UNTRUSTED)
                    ZMQ_MACRO(REVOCATION_OFFLINE_C)
                    ZMQ_MACRO(PKINIT_CLIENT_FAILURE)
                    ZMQ_MACRO(SMARTCARD_CERT_EXPIRED)
                    ZMQ_MACRO(NO_S4U_PROT_SUPPORT)
                    ZMQ_MACRO(CROSSREALM_DELEGATION_FAILURE)
                    ZMQ_MACRO(REVOCATION_OFFLINE_KDC)
                    ZMQ_MACRO(ISSUING_CA_UNTRUSTED_KDC)
                    ZMQ_MACRO(KDC_CERT_EXPIRED)
                    ZMQ_MACRO(KDC_CERT_REVOKED)
                    ZMQ_MACRO(INVALID_PARAMETER)
                    ZMQ_MACRO(DELEGATION_POLICY)
                    ZMQ_MACRO(POLICY_NLTM_ONLY)
                    ZMQ_MACRO(NO_CONTEXT)
                    ZMQ_MACRO(PKU2U_CERT_FAILURE)
                    ZMQ_MACRO(MUTUAL_AUTH_FAILED)
#undef ZMQ_MACRO                
            }        
        }
    };
} // namespace qpid

#endif  /*!QPID_NULLSASLSERVER_H*/
