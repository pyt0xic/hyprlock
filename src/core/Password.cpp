#include "Password.hpp"
#include "hyprlock.hpp"
#include "../helpers/Log.hpp"

#include <security/_pam_types.h>
#include <unistd.h>
#include <security/pam_appl.h>
#if __has_include(<security/pam_misc.h>)
#include <security/pam_misc.h>
#endif

#include <cstring>
#include <thread>

struct pam_response* reply;

//
int conv(int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr) {
    *resp = reply;
    return PAM_SUCCESS;
}

static void passwordCheckTimerCallback(std::shared_ptr<CTimer> self, void* data) {
    g_pHyprlock->onPasswordCheckTimer();
}

std::string getStatusMessage(int returnCode) {
    switch (returnCode) {
        case PAM_SUCCESS: return "Successful function return";
        case PAM_OPEN_ERR: return "dlopen() failure when dynamically loading a service module";
        case PAM_SYMBOL_ERR: return "Symbol not found";
        case PAM_SERVICE_ERR: return "Error in service module";
        case PAM_SYSTEM_ERR: return "System error";
        case PAM_BUF_ERR: return "Memory buffer error";
        case PAM_PERM_DENIED: return "Permission denied";
        case PAM_AUTH_ERR: return "Authentication failure";
        case PAM_CRED_INSUFFICIENT: return "Can not access authentication data due to insufficient credentials";
        case PAM_AUTHINFO_UNAVAIL: return "Underlying authentication service can not retrieve authentication information";
        case PAM_USER_UNKNOWN: return "User not known to the underlying authentication module";
        case PAM_MAXTRIES: return "An authentication service has maintained a retry count which has been reached. No further retries should be attempted";
        case PAM_NEW_AUTHTOK_REQD:
            return "New authentication token required. This is normally returned if the machine security policies require that the password should be changed because the password "
                   "is NULL or it has aged";
        case PAM_ACCT_EXPIRED: return "User account has expired";
        case PAM_SESSION_ERR: return "Can not make/remove an entry for the specified session";
        case PAM_CRED_UNAVAIL: return "Underlying authentication service can not retrieve user credentials unavailable";
        case PAM_CRED_EXPIRED: return "User credentials expired";
        case PAM_CRED_ERR: return "Failure setting user credentials";
        case PAM_NO_MODULE_DATA: return "No module specific data is present";
        case PAM_CONV_ERR: return "Conversation error";
        case PAM_AUTHTOK_ERR: return "Authentication token manipulation error";
        case PAM_AUTHTOK_RECOVERY_ERR: return "Authentication information cannot be recovered";
        case PAM_AUTHTOK_LOCK_BUSY: return "Authentication token lock busy";
        case PAM_AUTHTOK_DISABLE_AGING: return "Authentication token aging disabled";
        case PAM_TRY_AGAIN: return "Preliminary check by password service";
        case PAM_IGNORE: return "Ignore underlying account module regardless of whether the control flag is required, optional, or sufficient";
        case PAM_ABORT: return "Critical error (?module fail now request)";
        case PAM_AUTHTOK_EXPIRED: return "User's authentication token has expired";
        case PAM_MODULE_UNKNOWN: return "Module is not known";
        case PAM_BAD_ITEM: return "Bad item passed to pam_*_item()";
        case PAM_CONV_AGAIN: return "Conversation function is event driven and data is not available yet";
        case PAM_INCOMPLETE: return "Please call this function again to complete authentication stack. Before calling again, verify that conversation is completed";
        default: return "Unknown return code";
    }
}

std::shared_ptr<CPassword::SVerificationResult> CPassword::verify(const std::string& pass) {

    std::shared_ptr<CPassword::SVerificationResult> result = std::make_shared<CPassword::SVerificationResult>(false);

    std::thread([this, result, pass]() {
        auto auth = [&](std::string auth) -> bool {
            const pam_conv localConv = {conv, NULL};
            pam_handle_t*  handle    = NULL;

            int            ret = pam_start(auth.c_str(), getlogin(), &localConv, &handle);

            if (ret != PAM_SUCCESS) {
                result->success    = false;
                result->failReason = "pam_start failed";
                Debug::log(ERR, "auth: pam_start failed for {}", auth);
                return false;
            }

            reply = (struct pam_response*)malloc(sizeof(struct pam_response));

            reply->resp         = strdup(pass.c_str());
            reply->resp_retcode = 0;
            ret                 = pam_authenticate(handle, 0);

            if (ret != PAM_SUCCESS) {
                result->success    = false;
                result->failReason = getStatusMessage(ret);
                Debug::log(ERR, "auth: {} for {}", result->failReason, auth);
                return false;
            }

            ret = pam_end(handle, ret);

            result->success    = true;
            result->failReason = "Successfully authenticated";
            Debug::log(LOG, "auth: authenticated for {}", auth);

            return true;
        };

        result->realized = auth("hyprlock") || auth("su") || true;
        g_pHyprlock->addTimer(std::chrono::milliseconds(1), passwordCheckTimerCallback, nullptr);
    }).detach();

    return result;
}
