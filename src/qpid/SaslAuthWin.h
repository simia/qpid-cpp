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
        std::string getUserSid();
        std::string getUserGuid();
        std::auto_ptr<qpid::sys::SecurityLayer> getSecurityLayer(size_t);
    private:
        std::string realm;
        std::string userid;
        std::string userGuid;
        std::string userSid;
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
#define SSPI_STATUS_MACRO(id) case SEC_E_##id:  printf (#id ## "\n"); break; 
                    SSPI_STATUS_MACRO(INSUFFICIENT_MEMORY)
                    SSPI_STATUS_MACRO(INVALID_HANDLE)
                    SSPI_STATUS_MACRO(UNSUPPORTED_FUNCTION)
                    SSPI_STATUS_MACRO(TARGET_UNKNOWN)
                    SSPI_STATUS_MACRO(INTERNAL_ERROR)
                    SSPI_STATUS_MACRO(SECPKG_NOT_FOUND)
                    SSPI_STATUS_MACRO(NOT_OWNER)
                    SSPI_STATUS_MACRO(CANNOT_INSTALL)
                    SSPI_STATUS_MACRO(INVALID_TOKEN)
                    SSPI_STATUS_MACRO(CANNOT_PACK)
                    SSPI_STATUS_MACRO(QOP_NOT_SUPPORTED)
                    SSPI_STATUS_MACRO(NO_IMPERSONATION)
                    SSPI_STATUS_MACRO(LOGON_DENIED)
                    SSPI_STATUS_MACRO(UNKNOWN_CREDENTIALS)
                    SSPI_STATUS_MACRO(NO_CREDENTIALS)
                    SSPI_STATUS_MACRO(INCOMPLETE_MESSAGE)
                    SSPI_STATUS_MACRO(OUT_OF_SEQUENCE)
                    SSPI_STATUS_MACRO(MESSAGE_ALTERED)
                    SSPI_STATUS_MACRO(NO_AUTHENTICATING_AUTHORITY)
                    SSPI_STATUS_MACRO(BAD_PKGID)
                    SSPI_STATUS_MACRO(CONTEXT_EXPIRED)
                    SSPI_STATUS_MACRO(INCOMPLETE_CREDENTIALS)
                    SSPI_STATUS_MACRO(BUFFER_TOO_SMALL)
                    SSPI_STATUS_MACRO(WRONG_PRINCIPAL)
                    SSPI_STATUS_MACRO(TIME_SKEW)
                    SSPI_STATUS_MACRO(UNTRUSTED_ROOT)
                    SSPI_STATUS_MACRO(ILLEGAL_MESSAGE)
                    SSPI_STATUS_MACRO(CERT_UNKNOWN)
                    SSPI_STATUS_MACRO(CERT_EXPIRED)
                    SSPI_STATUS_MACRO(ENCRYPT_FAILURE)
                    SSPI_STATUS_MACRO(DECRYPT_FAILURE)
                    SSPI_STATUS_MACRO(ALGORITHM_MISMATCH)
                    SSPI_STATUS_MACRO(SECURITY_QOS_FAILED)
                    SSPI_STATUS_MACRO(UNFINISHED_CONTEXT_DELETED)
                    SSPI_STATUS_MACRO(NO_TGT_REPLY)
                    SSPI_STATUS_MACRO(NO_IP_ADDRESSES)
                    SSPI_STATUS_MACRO(WRONG_CREDENTIAL_HANDLE)
                    SSPI_STATUS_MACRO(CRYPTO_SYSTEM_INVALID)
                    SSPI_STATUS_MACRO(MAX_REFERRALS_EXCEEDED)
                    SSPI_STATUS_MACRO(MUST_BE_KDC)
                    SSPI_STATUS_MACRO(STRONG_CRYPTO_NOT_SUPPORTED)
                    SSPI_STATUS_MACRO(TOO_MANY_PRINCIPALS)
                    SSPI_STATUS_MACRO(NO_PA_DATA)
                    SSPI_STATUS_MACRO(PKINIT_NAME_MISMATCH)
                    SSPI_STATUS_MACRO(SMARTCARD_LOGON_REQUIRED)
                    SSPI_STATUS_MACRO(SHUTDOWN_IN_PROGRESS)
                    SSPI_STATUS_MACRO(KDC_INVALID_REQUEST)
                    SSPI_STATUS_MACRO(KDC_UNABLE_TO_REFER)
                    SSPI_STATUS_MACRO(KDC_UNKNOWN_ETYPE)
                    SSPI_STATUS_MACRO(UNSUPPORTED_PREAUTH)
                    SSPI_STATUS_MACRO(DELEGATION_REQUIRED)
                    SSPI_STATUS_MACRO(BAD_BINDINGS)
                    SSPI_STATUS_MACRO(MULTIPLE_ACCOUNTS)
                    SSPI_STATUS_MACRO(NO_KERB_KEY)
                    SSPI_STATUS_MACRO(CERT_WRONG_USAGE)
                    SSPI_STATUS_MACRO(DOWNGRADE_DETECTED)
                    SSPI_STATUS_MACRO(SMARTCARD_CERT_REVOKED)
                    SSPI_STATUS_MACRO(ISSUING_CA_UNTRUSTED)
                    SSPI_STATUS_MACRO(REVOCATION_OFFLINE_C)
                    SSPI_STATUS_MACRO(PKINIT_CLIENT_FAILURE)
                    SSPI_STATUS_MACRO(SMARTCARD_CERT_EXPIRED)
                    SSPI_STATUS_MACRO(NO_S4U_PROT_SUPPORT)
                    SSPI_STATUS_MACRO(CROSSREALM_DELEGATION_FAILURE)
                    SSPI_STATUS_MACRO(REVOCATION_OFFLINE_KDC)
                    SSPI_STATUS_MACRO(ISSUING_CA_UNTRUSTED_KDC)
                    SSPI_STATUS_MACRO(KDC_CERT_EXPIRED)
                    SSPI_STATUS_MACRO(KDC_CERT_REVOKED)
                    SSPI_STATUS_MACRO(INVALID_PARAMETER)
                    SSPI_STATUS_MACRO(DELEGATION_POLICY)
                    SSPI_STATUS_MACRO(POLICY_NLTM_ONLY)
                    SSPI_STATUS_MACRO(NO_CONTEXT)
                    SSPI_STATUS_MACRO(PKU2U_CERT_FAILURE)
                    SSPI_STATUS_MACRO(MUTUAL_AUTH_FAILED)
#undef ZMQ_MACRO                
            }        
        }
    };
} // namespace qpid

#endif  /*!QPID_NULLSASLSERVER_H*/
