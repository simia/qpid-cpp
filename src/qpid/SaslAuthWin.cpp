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

#include "SaslAuthWin.h"
#include "qpid/log/Statement.h"
#include "qpid/sys/SecurityLayer.h"
#include <assert.h>
#include <boost/format.hpp>

#include <thread>

namespace qpid {
    SspiSaslServer::SspiSaslServer(const std::string& r) : realm(r)
    {
        SecInvalidateHandle(&cred);
        SecInvalidateHandle(&context);

        DWORD len = 1024;
        TCHAR username[1025];

        GetUserNameEx(NameUserPrincipal, username, &len);

        maj_stat =
            AcquireCredentialsHandle(
                username,
                MICROSOFT_KERBEROS_NAME_A,
                SECPKG_CRED_INBOUND,
                NULL,
                NULL,
                NULL,
                NULL,
                &cred,
                &cred_expiry
            );

        maj_stat = SEC_I_CONTINUE_NEEDED;
    }

    SspiSaslServer::Status SspiSaslServer::start(const std::string& mechanism, const std::string* response, std::string& challenge)
    {       
        if (mechanism == "GSSAPI")
        {
            return CHALLENGE;
        }
        return FAIL;
    }

    void SspiSaslServer::acceptContext(const std::string* response)
    {
        unsigned long context_attr;
        TimeStamp expiry;

        recv_tok.cbBuffer = 0;
        recv_tok.BufferType = SECBUFFER_TOKEN;
        recv_tok.pvBuffer = NULL;
        recv_tok_desc.ulVersion = SECBUFFER_VERSION;
        recv_tok_desc.cBuffers = 1;
        recv_tok_desc.pBuffers = &recv_tok;

        recv_tok.cbBuffer = response->length();
        recv_tok.pvBuffer =
            static_cast<char *> (malloc(recv_tok.cbBuffer ? recv_tok.cbBuffer : 1));
        memcpy(recv_tok.pvBuffer, response->c_str(), recv_tok.cbBuffer);

        send_tok_desc.ulVersion = SECBUFFER_VERSION;
        send_tok_desc.cBuffers = 1;
        send_tok_desc.pBuffers = &send_tok;

        send_tok.BufferType = SECBUFFER_TOKEN;
        send_tok.cbBuffer = 0;
        send_tok.pvBuffer = nullptr;
        
        maj_stat = AcceptSecurityContext(
            &cred,
            SecIsValidHandle(&context) ? &context : nullptr,
            &recv_tok_desc,
            ASC_REQ_MUTUAL_AUTH | ASC_REQ_ALLOCATE_MEMORY, //FIXME: compute based on do_encryption
            SECURITY_NATIVE_DREP,
            &context,
            &send_tok_desc,
            &context_attr,
            &expiry);

        if (maj_stat < 0 || !SecIsValidHandle(&context))
        {
            checkStatus();
        }        
    }

    SspiSaslServer::Status SspiSaslServer::step(const std::string* response, std::string& challenge)
    {        
        acceptContext(response);
                
        if (maj_stat == SEC_E_OK)
        {
            QPID_LOG(debug, "SASL: authenticated");
            std::thread t([&]()
            {
                maj_stat = ImpersonateSecurityContext(&context);
                if (maj_stat != SEC_E_OK)
                {
                    std::cout << "Failed to impersonate\n";
                    return;
                }
                DWORD len = 1024;
                TCHAR guid[1025];
                TCHAR username[1025];

                GetUserNameEx(NameUniqueId, guid, &len);
                GetUserNameA(username, &len);
                
                userGuid = guid;
                userid = username;
                
            });
            t.join();
            return OK;
        }

        if (maj_stat == SEC_I_CONTINUE_NEEDED)
        {
            challenge = std::string(static_cast<const char*>(send_tok.pvBuffer), send_tok.cbBuffer);
            FreeContextBuffer(send_tok.pvBuffer);
            return CHALLENGE;
        }

        if (maj_stat != SEC_E_OK && maj_stat != SEC_I_CONTINUE_NEEDED)
        {
            return FAIL;
        }
        else if (maj_stat != SEC_I_CONTINUE_NEEDED)
        {
            int query_stat = QueryContextAttributes(&context, SECPKG_ATTR_SIZES, &context_sizes);
            if (query_stat < 0)
            {

            }
        }
        return FAIL;
    }
    std::string SspiSaslServer::getMechanisms()
    {
        return std::string("GSSAPI");
    }

    std::string SspiSaslServer::getUserid()
    {
        return userid;
    }

    std::string SspiSaslServer::getUserSid()
    {
        return userSid;
    }

    std::string SspiSaslServer::getUserGuid()
    {
        return userGuid;
    }

    std::auto_ptr<qpid::sys::SecurityLayer> SspiSaslServer::getSecurityLayer(size_t)
    {
        return std::auto_ptr<qpid::sys::SecurityLayer>();
    }

} // namespace qpid
