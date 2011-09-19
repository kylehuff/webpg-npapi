/**********************************************************\

  Auto-generated webpgPluginAPI.h

\**********************************************************/

#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "webpgPlugin.h"

#include <gpgme.h>

#ifndef H_webpgPluginAPI
#define H_webpgPluginAPI

struct genKeyParams {
    std::string key_type;
    std::string key_length;
    std::string subkey_type;
    std::string subkey_length;
    std::string name_real;
    std::string name_comment;
    std::string name_email;
    std::string expire_date;
    std::string passphrase;
};

struct genSubKeyParams {
    std::string keyid;
    std::string subkey_type;
    std::string subkey_length;
    std::string subkey_expire;
    bool sign_flag;
    bool enc_flag;
    bool auth_flag;
};


class webpgPluginAPI : public FB::JSAPIAuto
{
public:
    webpgPluginAPI(const webpgPluginPtr& plugin, const FB::BrowserHostPtr& host);
    virtual ~webpgPluginAPI();

    webpgPluginPtr getPlugin();

    FB::VariantMap gpg_status_map;
    FB::VariantMap get_gpg_status();

    void init();
    gpgme_ctx_t get_gpgme_ctx();
    FB::VariantMap getKeyList(const std::string& name, int secret_only);
    FB::VariantMap getNamedKey(const std::string& name);
    FB::VariantMap getPublicKeyList();
    FB::VariantMap getPrivateKeyList();

    std::string get_preference(const std::string& preference);
    FB::variant gpgSetPreference(const std::string& preference,
        const std::string& pref_value="");
    FB::variant gpgGetPreference(const std::string& preference);
    std::string getGPGConfigFilename();
    FB::variant setTempGPGOption(const std::string& option, const std::string& value=NULL);
    FB::variant restoreGPGConfig();
    FB::variant gpgSetHomeDir(const std::string& data);
    FB::variant gpgGetHomeDir();
    FB::variant getTemporaryPath();

    FB::variant gpgEncrypt(const std::string& data, const std::string& enc_to_keyid, 
        const std::string& enc_from_keyid=NULL, const std::string& sign=NULL);
    FB::variant gpgDecryptVerify(const std::string& data, int use_agent);
    FB::variant gpgDecrypt(const std::string& data);
    FB::variant gpgVerify(const std::string& data);
    FB::variant gpgSignText(const FB::VariantList& signers, const std::string& plain_text,
        int sign_mode);
    FB::variant gpgSignUID(const std::string& keyid, long uid,
        const std::string& with_keyid, long local_only=NULL, long trust_sign=NULL, 
        long trust_level=NULL);
    FB::variant gpgDeleteUIDSign(const std::string& keyid, long sign_uid,
        long signature);
    FB::variant gpgEnableKey(const std::string& keyid);
    FB::variant gpgDisableKey(const std::string& keyid);
    std::string gpgGenKey(const std::string& key_type, const std::string& key_length,
            const std::string& subkey_type, const std::string& subkey_length,
            const std::string& name_real, const std::string& name_comment,
            const std::string& name_email, const std::string& expire_date,
            const std::string& passphrase);
    void threaded_gpgGenKey(genKeyParams params);
    void threaded_gpgGenSubKey(genSubKeyParams params);
    FB::variant gpgImportKey(const std::string& ascii_key);
    FB::variant gpgDeleteKey(const std::string& keyid, int allow_secret);
    FB::variant gpgDeletePublicKey(const std::string& keyid);
    FB::variant gpgDeletePrivateKey(const std::string& keyid);
    FB::variant gpgDeletePrivateSubKey(const std::string& keyid, int key_idx);
    FB::variant gpgGenSubKey(const std::string& keyid, 
        const std::string& subkey_type, const std::string& subkey_length,
        const std::string& subkey_expire, bool sign_flag, bool enc_flag, bool auth_flag);
    FB::variant gpgSetKeyTrust(const std::string& keyid, long trust_level);
    FB::variant gpgAddUID(const std::string& keyid, const std::string& name,
        const std::string& email, const std::string& comment);
    FB::variant gpgDeleteUID(const std::string& keyid, long uid_idx);
    FB::variant gpgSetPrimaryUID(const std::string& keyid, long uid_idx);
    FB::variant gpgSetKeyExpire(const std::string& keyid, long key_idx, long expire);
    FB::variant gpgSetPubkeyExpire(const std::string& keyid, long expire);
    FB::variant gpgSetSubkeyExpire(const std::string& keyid, long key_idx, long expire);
    FB::variant gpgExportPublicKey(const std::string& keyid);
    FB::variant gpgRevokeItem(const std::string& keyid, const std::string& item, int key_idx,
        int uid_idx, int sig_idx, int reason_idx, const std::string& desc);
    FB::variant gpgRevokeKey(const std::string& keyid, int key_idx, int reason,
        const std::string &desc);
    FB::variant gpgRevokeUID(const std::string& keyid, int uid_idx, int reason,
        const std::string &desc);
    FB::variant gpgRevokeSignature(const std::string& keyid, int uid_idx, int sig_idx,
        int reason, const std::string &desc);
    FB::variant gpgChangePassphrase(const std::string& keyid);

    std::string get_version();
    bool gpgconf_detected();
    std::string original_gpg_config;

    // void (*gpgme_progress_cb_t)(void *hook, const char *what, int type, int current, int total)
    static void progress_cb(
        void *self, const char *what,
        int type, int current, int total
    );

    // gpgme_error_t (*gpgme_passphrase_cb_t)(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd)
//    gpgme_error_t passdefunct_cb(
//        void *self, const char *uid_hint,
//        const char *passphrase_info, int prev_was_bad, int fd
//    );

    std::string gpgGenKeyWorker(const std::string& key_type, 
        const std::string& key_length,
        const std::string& subkey_type,
        const std::string& subkey_length,
        const std::string& name_real,
        const std::string& name_comment,
        const std::string& name_email,
        const std::string& expire_date,
        const std::string& passphrase,
        void* APIObj, void(*cb_status)(void *self,
            const char *what,
            int type,
            int current,
            int total
        )
    );

    /*
        static class method which accepts the calling object as a parameter
            so it can thread a member function
    */
    static void genKeyThreadCaller(webpgPluginAPI* api,
        genKeyParams params)
    {
        api->threaded_gpgGenKey(params);
    };

    FB::variant gpgGenSubKeyWorker(const std::string& keyid, 
        const std::string& subkey_type,
        const std::string& subkey_length,
        const std::string& subkey_expire,
        bool sign_flag,
        bool enc_flag,
        bool auth_flag,
        void* APIObj, void(*cb_status)(void *self,
            const char *what,
            int type,
            int current,
            int total
        )
    );

    static void genSubKeyThreadCaller(webpgPluginAPI* api,
        genSubKeyParams params)
    {
        api->threaded_gpgGenSubKey(params);
    };

    // Event helpers
    FB_JSAPI_EVENT(fired, 3, (const FB::variant&, bool, int));
    FB_JSAPI_EVENT(echo, 2, (const FB::variant&, const int));
    FB_JSAPI_EVENT(notify, 0, ());

private:
    webpgPluginWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;

};

#endif // H_webpgPluginAPI

