#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"
#include "DOM/Window.h"
#include "global/config.h"

#include "webpgPluginAPI.h"
#include "keyedit.h"

/*
 * Define non-member methods/inlines
 */

#ifdef HAVE_W32_SYSTEM
#define __func__ __FUNCTION__
#endif

FB::VariantMap get_error_map(const std::string& method,
                        gpgme_error_t gpg_error_code,
                        const std::string& error_string,
                        int line, const std::string& file,
                        std::string data="")
{
    FB::VariantMap error_map_obj;
    error_map_obj["error"] = true;
    error_map_obj["method"] = method;
    error_map_obj["gpg_error_code"] = gpg_error_code;
    error_map_obj["error_string"] = error_string;
    error_map_obj["line"] = line;
    error_map_obj["file"] = file;
    if (data.length())
        error_map_obj["data"] = data;
    return error_map_obj;
}

/* An inline method to convert a null char */
inline
static const char *
    nonnull (const char *s)
    {
      return s? s :"[none]";
    }

std::string LoadFileAsString(const std::string& filename)
{
    std::ifstream fin(filename.c_str());

    if(!fin)
    {
        return "";
    }

    std::ostringstream oss;
    oss << fin.rdbuf();

    return oss.str();
}

static bool gpgme_invalid = false;

///////////////////////////////////////////////////////////////////////////////
/// @fn webpgPluginAPI::webpgPluginAPI(const webpgPluginPtr& plugin, const FB::BrowserHostPtr host)
///
/// @brief  Constructor for your JSAPI object.  You should register your methods, properties, and events
///         that should be accessible to Javascript from here.
///
/// @see FB::JSAPIAuto::registerMethod
/// @see FB::JSAPIAuto::registerProperty
/// @see FB::JSAPIAuto::registerEvent
///////////////////////////////////////////////////////////////////////////////
webpgPluginAPI::webpgPluginAPI(const webpgPluginPtr& plugin, const FB::BrowserHostPtr& host) : m_plugin(plugin), m_host(host)
{
    static bool allow_op = true;
#ifdef _EXTENSIONIZE
    std::string location = m_host->getDOMWindow()->getLocation();
    size_t firefox_ext = location.find("chrome://");
    size_t chrome_ext = location.find("chrome-extension://");
    if (chrome_ext != std::string::npos || firefox_ext != std::string::npos)
        allow_op = true;
    else
        allow_op = false;
#endif

    if (allow_op == true) {
        registerMethod("getKeyList", make_method(this, &webpgPluginAPI::getKeyList));
        registerMethod("getPublicKeyList", make_method(this, &webpgPluginAPI::getPublicKeyList));
        registerMethod("getPrivateKeyList", make_method(this, &webpgPluginAPI::getPrivateKeyList));
        registerMethod("getNamedKey", make_method(this, &webpgPluginAPI::getNamedKey));
        registerMethod("gpgSetPreference", make_method(this, &webpgPluginAPI::gpgSetPreference));
        registerMethod("gpgGetPreference", make_method(this, &webpgPluginAPI::gpgGetPreference));
        registerMethod("gpgSetHomeDir", make_method(this, &webpgPluginAPI::gpgSetHomeDir));
        registerMethod("gpgGetHomeDir", make_method(this, &webpgPluginAPI::gpgGetHomeDir));
        registerMethod("gpgEncrypt", make_method(this, &webpgPluginAPI::gpgEncrypt));
        registerMethod("gpgSymmetricEncrypt", make_method(this, &webpgPluginAPI::gpgSymmetricEncrypt));
        registerMethod("gpgDecrypt", make_method(this, &webpgPluginAPI::gpgDecrypt));
        registerMethod("gpgVerify", make_method(this, &webpgPluginAPI::gpgVerify));
        registerMethod("gpgSignText", make_method(this, &webpgPluginAPI::gpgSignText));
        registerMethod("gpgSignUID", make_method(this, &webpgPluginAPI::gpgSignUID));
        registerMethod("gpgEnableKey", make_method(this, &webpgPluginAPI::gpgEnableKey));
        registerMethod("gpgDisableKey", make_method(this, &webpgPluginAPI::gpgDisableKey));
        registerMethod("gpgDeleteUIDSign", make_method(this, &webpgPluginAPI::gpgDeleteUIDSign));
        registerMethod("gpgGenKey", make_method(this, &webpgPluginAPI::gpgGenKey));
        registerMethod("gpgGenSubKey", make_method(this, &webpgPluginAPI::gpgGenSubKey));
        registerMethod("gpgImportKey", make_method(this, &webpgPluginAPI::gpgImportKey));
        registerMethod("gpgDeletePublicKey", make_method(this, &webpgPluginAPI::gpgDeletePublicKey));
        registerMethod("gpgDeletePrivateKey", make_method(this, &webpgPluginAPI::gpgDeletePrivateKey));
        registerMethod("gpgDeletePrivateSubKey", make_method(this, &webpgPluginAPI::gpgDeletePrivateSubKey));
        registerMethod("gpgSetKeyTrust", make_method(this, &webpgPluginAPI::gpgSetKeyTrust));
        registerMethod("gpgAddUID", make_method(this, &webpgPluginAPI::gpgAddUID));
        registerMethod("gpgDeleteUID", make_method(this, &webpgPluginAPI::gpgDeleteUID));
        registerMethod("gpgSetPrimaryUID", make_method(this, &webpgPluginAPI::gpgSetPrimaryUID));
        registerMethod("gpgSetSubkeyExpire", make_method(this, &webpgPluginAPI::gpgSetSubkeyExpire));
        registerMethod("gpgSetPubkeyExpire", make_method(this, &webpgPluginAPI::gpgSetPubkeyExpire));
        registerMethod("gpgExportPublicKey", make_method(this, &webpgPluginAPI::gpgExportPublicKey));
        registerMethod("gpgRevokeKey", make_method(this, &webpgPluginAPI::gpgRevokeKey));
        registerMethod("gpgRevokeUID", make_method(this, &webpgPluginAPI::gpgRevokeUID));
        registerMethod("gpgRevokeSignature", make_method(this, &webpgPluginAPI::gpgRevokeSignature));
        registerMethod("gpgChangePassphrase", make_method(this, &webpgPluginAPI::gpgChangePassphrase));

        registerMethod("setTempGPGOption", make_method(this, &webpgPluginAPI::setTempGPGOption));
        registerMethod("restoreGPGConfig", make_method(this, &webpgPluginAPI::restoreGPGConfig));
        registerMethod("getTemporaryPath", make_method(this, &webpgPluginAPI::getTemporaryPath));

        registerEvent("onkeygenprogress");
        registerEvent("onkeygencomplete");
    }

    // Read-only property
    registerProperty("version",
                     make_property(this,
                        &webpgPluginAPI::get_version));

    registerProperty("webpg_status",
                    make_property(this,
                        &webpgPluginAPI::get_webpg_status));

    registerProperty("gpgconf_detected",
                     make_property(this,
                        &webpgPluginAPI::gpgconf_detected));

    webpgPluginAPI::init();
}

///////////////////////////////////////////////////////////////////////////////
/// @fn webpgPluginAPI::~webpgPluginAPI()
///
/// @brief  Destructor.  Remember that this object will not be released until
///         the browser is done with it; this will almost definitely be after
///         the plugin is released.
///////////////////////////////////////////////////////////////////////////////
webpgPluginAPI::~webpgPluginAPI()
{
}

///////////////////////////////////////////////////////////////////////////////
/// @fn webpgPluginPtr webpgPluginAPI::getPlugin()
///
/// @brief  Gets a reference to the plugin that was passed in when the object
///         was created.  If the plugin has already been released then this
///         will throw a FB::script_error that will be translated into a
///         javascript exception in the page.
///////////////////////////////////////////////////////////////////////////////
webpgPluginPtr webpgPluginAPI::getPlugin()
{
    webpgPluginPtr plugin(m_plugin.lock());
    if (!plugin) {
        throw FB::script_error("The plugin is invalid");
    }
    return plugin;
}

void webpgPluginAPI::init()
{
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    FB::VariantMap error_map;
    FB::VariantMap response;
    FB::VariantMap protocol_info, plugin_info;
    gpgme_engine_info_t engine_info;

    plugin_info["source_url"] = m_host->getDOMWindow()->getLocation();
    plugin_info["path"] = getPlugin()->getPluginPath();
    plugin_info["params"] = getPlugin()->getPluginParams();
    plugin_info["version"] = FBSTRING_PLUGIN_VERSION;
    response["plugin"] = plugin_info;

#ifdef _EXTENSIONIZE
    response["extensionize"] = true;
    std::string location = m_host->getDOMWindow()->getLocation();
    size_t firefox_ext = location.find("chrome://");
    size_t chrome_ext = location.find("chrome-extension://");
    response["extension"] = (chrome_ext != std::string::npos) ?
        "chrome" : (firefox_ext != std::string::npos) ? "firefox" : "unknown";
#endif

    /* Initialize the locale environment.
     * The function `gpgme_check_version` must be called before any other
     * function in the library, because it initializes the thread support
     * subsystem in GPGME. (from the info page) */
    std::string gpgme_version = (char *) gpgme_check_version(NULL);

    setlocale (LC_ALL, "");
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifdef LC_MESSAGES
    gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

    err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
    if (err != GPG_ERR_NO_ERROR)
        error_map = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    if (error_map.size()) {
        response["openpgp_valid"] = false;
        response["error"] = true;
        response["error_map"] = error_map;
        webpgPluginAPI::webpg_status_map = error_map;
        gpgme_invalid = true;
        return;
    }

    //err = gpgme_new (&ctx);
    //if (err != GPG_ERR_NO_ERROR)
    //    error_map = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    ctx = get_gpgme_ctx();

    if (error_map.size()) {
        response["gpgme_valid"] = false;
        response["error"] = true;
        gpgme_invalid = true;
    } else {
        response["error"] = false;
        response["gpgme_valid"] = true;
        response["gpgconf_detected"] = gpgconf_detected();
        if (!gpgconf_detected())
            response["gpgconf_response"] = gpgme_strerror (gpgme_engine_check_version (GPGME_PROTOCOL_GPGCONF));
        response["gpgme_version"] = gpgme_version;
        engine_info = gpgme_ctx_get_engine_info (ctx);
        if (engine_info) {
            if (engine_info->file_name)
                protocol_info["file_name"] = (char *) engine_info->file_name;
            if (engine_info->version)
                protocol_info["version"] = (char *) engine_info->version;
            if (engine_info->home_dir)
                protocol_info["home_dir"] = (char *) engine_info->home_dir;
            if (engine_info->req_version)
                protocol_info["req_version"] = (char *) engine_info->req_version;
            response[(char *) gpgme_get_protocol_name (engine_info->protocol)] = protocol_info;
        } else {
            response["OpenPGP"] = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
        }
    }

    response["GNUPGHOME"] = GNUPGHOME;

    // Retrieve the GPG_AGENT_INFO environment variable
    char *gpg_agent_info = getenv("GPG_AGENT_INFO");

    if (gpg_agent_info != NULL) {
        response["gpg_agent_info"] = gpg_agent_info;
    } else {
        response["gpg_agent_info"] = "unknown";
    }

    if (ctx)
        gpgme_release (ctx);

    webpgPluginAPI::webpg_status_map = response;
};

gpgme_ctx_t webpgPluginAPI::get_gpgme_ctx()
{
    gpgme_ctx_t ctx;
    gpgme_error_t err;

    setlocale (LC_ALL, "");
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifdef LC_MESSAGES
    gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

    // Check the GNUPGHOME variable, if not null, set that
    if (GNUPGHOME.length() > 0) {
        err = gpgme_new (&ctx);
        gpgme_engine_info_t engine_info = gpgme_ctx_get_engine_info (ctx);
        if (engine_info) {
            err = gpgme_ctx_set_engine_info (ctx, engine_info->protocol,
                engine_info->file_name,
                GNUPGHOME.c_str());
        } else {
            std::string env = "GNUPGHOME=" + GNUPGHOME;
            putenv(strdup(env.c_str()));
            err = gpgme_new (&ctx);
        }
    } else {
        err = gpgme_new (&ctx);
    }

    gpgme_set_textmode (ctx, 1);
    gpgme_set_armor (ctx, 1);

    return ctx;
}

std::string webpgPluginAPI::getGPGConfigFilename() {
    std::string config_path = "";

    if (GNUPGHOME.length() > 0) {
        config_path = GNUPGHOME;
    } else {
        char const* home = getenv("HOME");
        if (home || (home = getenv("USERPROFILE"))) {
          config_path = home;
        } else {
          char const *hdrive = getenv("HOMEDRIVE"),
            *hpath = getenv("HOMEPATH");
          assert(hdrive);  // or other error handling
          assert(hpath);
          config_path = std::string(hdrive) + hpath;
        }
    }

#ifdef HAVE_W32_SYSTEM
    config_path += "\\Application Data\\gnupg\\gpg.conf";
#else
    config_path += "/.gnupg/gpg.conf";
#endif

    return config_path;
}

FB::variant webpgPluginAPI::setTempGPGOption(const std::string& option, const std::string& value) {

    std::string result;
    std::string config_path = webpgPluginAPI::getGPGConfigFilename();
    std::string tmp_config_path = config_path + "-webpg.save";

    std::string gpgconfigfile = LoadFileAsString(config_path);

    if (gpgconfigfile.length()) {
        // Test if we already made a backup, if not, make one!
        std::ifstream tmp_config_exists(tmp_config_path.c_str());
        if (!tmp_config_exists) {
            // Backup the current contents
            std::ofstream tmp_file(tmp_config_path.c_str());
            if (!tmp_file)
                return "error opening temp_file";
            tmp_file << gpgconfigfile;
            tmp_file.close();
        }

        gpgconfigfile += option;
        if (value.length())
            gpgconfigfile += " " + value;
        gpgconfigfile += "\n";

        std::ofstream gpg_file(config_path.c_str());
        if (!gpg_file)
            return "error writing gpg_file";
        gpg_file << gpgconfigfile;
        gpg_file.close();
    }

    if (gpgconfigfile.length())
        result = "Set ";
    else
        result = "Unable to set ";

    if (value.length())
        result += "'" + option + " = " + value + "' in file: " + config_path;
    else
        result += "'" + option + "' in file: " + config_path;

    return result;
}

FB::variant webpgPluginAPI::restoreGPGConfig() {

    std::string config_path = getGPGConfigFilename();
    std::string tmp_config_path = config_path + "-webpg.save";

    std::string restore_string;
    std::string result = "gpg config restored from memory";

    if (!original_gpg_config.length()) {
        // We don't have the original file in memory, lets restore the backup
        original_gpg_config = LoadFileAsString(tmp_config_path);
        if (!original_gpg_config.length())
            return "error restoring gpg_file from disk";
        result = "gpg config restored from disk.";
    }

    std::ofstream gpg_file(config_path.c_str());

    if (!gpg_file)
        return "error restoring gpg_file from memory";

    gpg_file << original_gpg_config;
    gpg_file.close();

    remove(tmp_config_path.c_str());
    original_gpg_config = "";

    return result;
}

FB::variant webpgPluginAPI::gpgSetHomeDir(const std::string& gnupg_path)
{
    GNUPGHOME = gnupg_path;
    return GNUPGHOME;
}

FB::variant webpgPluginAPI::gpgGetHomeDir()
{
    return GNUPGHOME;
}

FB::variant webpgPluginAPI::getTemporaryPath()
{
    char *gnupghome_envvar = getenv("TEMP");
    if (gnupghome_envvar != NULL) {
        return gnupghome_envvar;
    } else {
        return "";
    }
}

FB::VariantMap webpgPluginAPI::get_webpg_status()
{
    webpgPluginAPI::init();
    webpgPluginAPI::webpg_status_map["edit_status"] = edit_status;
    return webpgPluginAPI::webpg_status_map;
}

/*
    This method retrieves all keys matching name, or if name is left empty,
        returns all keys in the keyring.
    NOTE: This method is not exposed to the NPAPI plugin, it is only called internally
*/
FB::VariantMap webpgPluginAPI::getKeyList(const std::string& name, int secret_only)
{
    /* declare variables */
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_key_t key;
    gpgme_keylist_result_t result;
    gpgme_user_id_t uid;
    gpgme_key_sig_t sig;
    gpgme_subkey_t subkey;
    FB::VariantMap keylist_map;

    FB::VariantMap uid_map;

    /* set protocol to use in our context */
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    if(err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    /* apply the keylist mode to the context and set
        the keylist_mode 
        NOTE: The keylist mode flag GPGME_KEYLIST_MODE_SIGS 
            returns the signatures of UIDS with the key */
    gpgme_set_keylist_mode (ctx, (gpgme_get_keylist_mode (ctx)
                                | GPGME_KEYLIST_MODE_SIGS
                                | GPGME_KEYLIST_MODE_VALIDATE));

    /* gpgme_op_keylist_start (gpgme_ctx_t ctx, const char *pattern, int secret_only) */
    if (name.length() > 0){ // limit key listing to search criteria 'name'
        err = gpgme_op_keylist_start (ctx, name.c_str(), secret_only);
    } else { // list all keys
        err = gpgme_op_keylist_start (ctx, NULL, secret_only);
    }
    if(err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    while (!(err = gpgme_op_keylist_next (ctx, &key)))
     {
        /*declare nuids (Number of UIDs) 
            and nsigs (Number of signatures)
            and nsubs (Number of Subkeys)*/
        int nuids;
        int nsigs;
        int nsubs;
        int tnsigs;
        FB::VariantMap key_map;

        /* if secret keys being returned, re-retrieve the key so we get all of the key info */ 
        if(secret_only != 0 && key->subkeys && key->subkeys->keyid)
            err = gpgme_get_key (ctx, key->subkeys->keyid, &key, 0);

        /* iterate through the keys/subkeys and add them to the key_map object */
        if (key->uids && key->uids->name)
            key_map["name"] = nonnull (key->uids->name);
        if (key->subkeys && key->subkeys->fpr)
            key_map["fingerprint"] = nonnull (key->subkeys->fpr);
        if (key->uids && key->uids->email)
            key_map["email"] = nonnull (key->uids->email);
        key_map["expired"] = key->expired? true : false;
        key_map["revoked"] = key->revoked? true : false;
        key_map["disabled"] = key->disabled? true : false;
        key_map["invalid"] = key->invalid? true : false;
        key_map["secret"] = key->secret? true : false;
        key_map["protocol"] = key->protocol == GPGME_PROTOCOL_OpenPGP? "OpenPGP":
            key->protocol == GPGME_PROTOCOL_CMS? "CMS":
            key->protocol == GPGME_PROTOCOL_UNKNOWN? "Unknown": "[?]";
        key_map["can_encrypt"] = key->can_encrypt? true : false;
        key_map["can_sign"] = key->can_sign? true : false;
        key_map["can_certify"] = key->can_certify? true : false;
        key_map["can_authenticate"] = key->can_authenticate? true : false;
        key_map["is_qualified"] = key->is_qualified? true : false;
        key_map["owner_trust"] = key->owner_trust == GPGME_VALIDITY_UNKNOWN? "unknown":
            key->owner_trust == GPGME_VALIDITY_UNDEFINED? "undefined":
            key->owner_trust == GPGME_VALIDITY_NEVER? "never":
            key->owner_trust == GPGME_VALIDITY_MARGINAL? "marginal":
            key->owner_trust == GPGME_VALIDITY_FULL? "full":
            key->owner_trust == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]";

        FB::VariantMap subkeys_map;
        for (nsubs=0, subkey=key->subkeys; subkey; subkey = subkey->next, nsubs++) {
            FB::VariantMap subkey_item_map;
            subkey_item_map["subkey"] = nonnull (subkey->fpr);
            subkey_item_map["expired"] = subkey->expired? true : false;
            subkey_item_map["revoked"] = subkey->revoked? true : false;
            subkey_item_map["disabled"] = subkey->disabled? true : false;
            subkey_item_map["invalid"] = subkey->invalid? true : false;
            subkey_item_map["secret"] = subkey->secret? true : false;
            subkey_item_map["can_encrypt"] = subkey->can_encrypt? true : false;
            subkey_item_map["can_sign"] = subkey->can_sign? true : false;
            subkey_item_map["can_certify"] = subkey->can_certify? true : false;
            subkey_item_map["can_authenticate"] = subkey->can_authenticate? true : false;
            subkey_item_map["is_qualified"] = subkey->is_qualified? true : false;
            subkey_item_map["algorithm"] = subkey->pubkey_algo;
            subkey_item_map["algorithm_name"] = nonnull (gpgme_pubkey_algo_name(subkey->pubkey_algo));
            subkey_item_map["size"] = subkey->length;
            subkey_item_map["created"] = subkey->timestamp;
            subkey_item_map["expires"] = subkey->expires;
            subkeys_map[i_to_str(nsubs)] = subkey_item_map;
        }

        key_map["subkeys"] = subkeys_map;

        FB::VariantMap uids_map;
        for (nuids=0, uid=key->uids; uid; uid = uid->next, nuids++) {
            FB::VariantMap uid_item_map;
            uid_item_map["uid"] = nonnull (uid->name);
            uid_item_map["email"] = nonnull (uid->email);
            uid_item_map["comment"] = nonnull (uid->comment);
            uid_item_map["invalid"] = uid->invalid? true : false;
            uid_item_map["revoked"] = uid->revoked? true : false;
            tnsigs = 0;
            for (nsigs=0, sig=uid->signatures; sig; sig = sig->next, nsigs++) {
                tnsigs += 1;
            }
            uid_item_map["signatures_count"] = tnsigs;

            FB::VariantMap signatures_map;

            for (nsigs=0, sig=uid->signatures; sig; sig = sig->next, nsigs++) {
                FB::VariantMap signature_map;
                signature_map["keyid"] = nonnull (sig->keyid);
                signature_map["algorithm"] = sig->pubkey_algo;
                signature_map["algorithm_name"] = nonnull (gpgme_pubkey_algo_name(sig->pubkey_algo));
                signature_map["revoked"] = sig->revoked? true : false;
                signature_map["expired"] = sig->expired? true : false;
                signature_map["invalid"] = sig->invalid? true : false;
                signature_map["exportable"] = sig->exportable? true : false;
                signature_map["created"] = sig->timestamp;
                signature_map["expires"] = sig->expires;
                signature_map["uid"] = nonnull (sig->uid);
                signature_map["name"] = nonnull (sig->name);
                signature_map["comment"] = nonnull (sig->comment);
                signature_map["email"] = nonnull (sig->email);
                signatures_map[i_to_str(nsigs)] = signature_map;
            }
            uid_item_map["signatures"] = signatures_map;
            uid_item_map["validity"] = uid->validity == GPGME_VALIDITY_UNKNOWN? "unknown":
                uid->validity == GPGME_VALIDITY_UNDEFINED? "undefined":
                uid->validity == GPGME_VALIDITY_NEVER? "never":
                uid->validity == GPGME_VALIDITY_MARGINAL? "marginal":
                uid->validity == GPGME_VALIDITY_FULL? "full":
                uid->validity == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]";
            uids_map[i_to_str(nuids)] = uid_item_map;
        }
        key_map["uids"] = uids_map;
        keylist_map[key->subkeys->keyid] = key_map;
        gpgme_key_unref (key);
    }

    if (gpg_err_code (err) != GPG_ERR_EOF) exit(6);
    err = gpgme_op_keylist_end (ctx);
    if(err != GPG_ERR_NO_ERROR) exit(7);
    result = gpgme_op_keylist_result (ctx);
    if (result->truncated)
     {
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
     }
    gpgme_release (ctx);
    return keylist_map;
}

/*
    This method executes webpgPlugin.getKeyList with an empty string and
        secret_only=0 which returns all Public Keys in the keyring.
*/
FB::variant webpgPluginAPI::getPublicKeyList()
{
    // Retrieve the public keylist
    FB::variant public_keylist = webpgPluginAPI::getKeyList("", 0);

    // Retrieve a reference to the DOM Window
    FB::DOM::WindowPtr window = m_host->getDOMWindow();

    // Check if the DOM Window has an in-built JSON Parser
    if (window && window->getJSObject()->HasProperty("JSON")) {
        // Convert the VariantMap to a Json::Value object
        Json::Value json_value = FB::variantToJsonValue(public_keylist);

        // Create a writer that will convert the object to a string
        Json::FastWriter writer;

        // Create a reference to the browswer JSON object
        FB::JSObjectPtr obj = window->getProperty<FB::JSObjectPtr>("JSON");

        return obj->Invoke("parse", FB::variant_list_of(writer.write(json_value)));
    } else {
        // No browser JSON parser detected, falling back to return of FB::variant
        return public_keylist;
    }
}

/*
    This method executes webpgPlugin.getKeyList with an empty string and
        secret_only=1 which returns all keys in the keyring which
        the user has the corrisponding secret key.
*/
FB::variant webpgPluginAPI::getPrivateKeyList()
{
    // Retrieve the private keylist
    FB::variant private_keylist = webpgPluginAPI::getKeyList("", 1);

    // Retrieve a reference to the DOM Window
    FB::DOM::WindowPtr window = m_host->getDOMWindow();

    // Check if the DOM Window has an in-built JSON Parser
    if (window && window->getJSObject()->HasProperty("JSON")) {
        // Convert the VariantMap to a Json::Value object
        Json::Value json_value = FB::variantToJsonValue(private_keylist);

        // Create a writer that will convert the object to a string
        Json::FastWriter writer;

        // Create a reference to the browswer JSON object
        FB::JSObjectPtr obj = window->getProperty<FB::JSObjectPtr>("JSON");

        return obj->Invoke("parse", FB::variant_list_of(writer.write(json_value)));
    } else {
        // No browser JSON parser detected, falling back to return of FB::variant
        return private_keylist;
    }
}

/*
    This method just calls webpgPlugin.getKeyList with a name/email
        as the parameter
*/
FB::variant webpgPluginAPI::getNamedKey(const std::string& name)
{
    // Retrieve the keylist as a VariantMap
    FB::variant keylist = webpgPluginAPI::getKeyList(name, 0);

    // Retrieve a reference to the DOM Window
    FB::DOM::WindowPtr window = m_host->getDOMWindow();

    // Check if the DOM Window has an in-built JSON Parser
    if (window && window->getJSObject()->HasProperty("JSON")) {
        // Convert the VariantMap to a Json::Value object
        Json::Value json_value = FB::variantToJsonValue(keylist);

        // Create a writer that will convert the object to a string
        Json::FastWriter writer;

        // Create a reference to the browswer JSON object
        FB::JSObjectPtr obj = window->getProperty<FB::JSObjectPtr>("JSON");

        return obj->Invoke("parse", FB::variant_list_of(writer.write(json_value)));
    } else {
        // No browser JSON parser detected, falling back to return of FB::variant
        return keylist;
    }
}

bool webpgPluginAPI::gpgconf_detected() {
    gpgme_error_t err;
    std::string cfg_present;
    err = gpgme_engine_check_version (GPGME_PROTOCOL_GPGCONF);
    if (err && err != GPG_ERR_NO_ERROR) {
        return false;
    }
    return true;
}

std::string webpgPluginAPI::get_preference(const std::string& preference)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_conf_comp_t conf, comp;
    gpgme_conf_opt_t opt;
    std::string return_value;

    err = gpgme_op_conf_load (ctx, &conf);

    comp = conf;
    while (comp && strcmp (comp->name, "gpg"))
        comp = comp->next;

    if (comp) {
        opt = comp->options;
        while (opt && strcmp (opt->name, (char *) preference.c_str())){
            opt = opt->next;
        }

        if (opt->value) {
            return_value = opt->value->value.string;
        } else {
            return_value = "blank";
        }
	}

    gpgme_conf_release (conf);

    return return_value;

}

FB::variant webpgPluginAPI::gpgSetPreference(const std::string& preference, const std::string& pref_value)
{
	gpgme_error_t err;
	gpgme_protocol_t proto = GPGME_PROTOCOL_OpenPGP;
    err = gpgme_engine_check_version (proto);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_conf_comp_t conf, comp;
    FB::variant response;
    std::string return_code;

    err = gpgme_op_conf_load (ctx, &conf);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_conf_arg_t original_arg, arg;
    gpgme_conf_opt_t opt;

    if (pref_value.length())
        err = gpgme_conf_arg_new (&arg, GPGME_CONF_STRING, (char *) pref_value.c_str());
    else
        err = gpgme_conf_arg_new (&arg, GPGME_CONF_STRING, NULL);

    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    comp = conf;
    while (comp && strcmp (comp->name, "gpg"))
        comp = comp->next;

    if (comp) {
        opt = comp->options;

        while (opt && strcmp (opt->name, (char *) preference.c_str())){
            opt = opt->next;
        }

        if (!opt) {
            return "unable to locate that option in this context";
        }

        if (opt->value && pref_value.length()) {
            original_arg = opt->value;
        } else {
            original_arg = opt->value;
            return_code = "blank";
        }

        /* if the new argument and original argument are the same, return 0, 
            there is nothing to do. */
        if (pref_value.length() && original_arg && 
            !strcmp (original_arg->value.string, arg->value.string)) {
            return "0";
        }

        if (opt) {
            if (!strcmp(pref_value.c_str(), "blank") || pref_value.length() < 1)
                err = gpgme_conf_opt_change (opt, 0, NULL);
            else
                err = gpgme_conf_opt_change (opt, 0, arg);

            if (err != GPG_ERR_NO_ERROR)
                return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

            err = gpgme_op_conf_save (ctx, comp);
            if (err != GPG_ERR_NO_ERROR)
                return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
        }
    }

    if (conf)
        gpgme_conf_release (conf);

    if (ctx)
        gpgme_release (ctx);

    if (!return_code.length())
        return_code = strdup(original_arg->value.string);

    return return_code;
}


FB::variant webpgPluginAPI::gpgGetPreference(const std::string& preference)
{
	gpgme_error_t err;
	gpgme_protocol_t proto = GPGME_PROTOCOL_OpenPGP;
    err = gpgme_engine_check_version (proto);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_conf_comp_t conf, comp;
    FB::VariantMap response;
    response["error"] = false;

    err = gpgme_op_conf_load (ctx, &conf);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_conf_arg_t arg;
    gpgme_conf_opt_t opt;

    comp = conf;
    while (comp && strcmp (comp->name, "gpg"))
        comp = comp->next;

    if (comp) {
        opt = comp->options;

        while (opt && strcmp (opt->name, (char *) preference.c_str())){
            opt = opt->next;
        }

        if (opt) {
            if (opt->value) {
                arg = opt->value;
                response["value"] = strdup(arg->value.string);
            } else {
                response["value"] = "";
            }
        } else {
            response["error"] = true;
            response["error_string"] = "unable to locate that option in this context";
        }
    }

    if (conf)
        gpgme_conf_release (conf);

    if (ctx)
        gpgme_release (ctx);

    return response;
}

/*
    This method passes a string to encrypt, a list of keys to encrypt to calls
        webpgPlugin.gpgEncrypt. This method returns a string of encrypted data.
*/
/* This method accepts 3 parameters, data, enc_to_keyid 
    and sign [optional; default: 0:NULL:false]
    the return value is a string buffer of the result */
FB::variant webpgPluginAPI::gpgEncrypt(const std::string& data, 
        const FB::VariantList& enc_to_keyids, bool sign)
{
    /* declare variables */
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t in, out;
#ifdef HAVE_W32_SYSTEM
    // FIXME: W32 doesn't like the array sized by the contents of the
    // enc_to_keyids - for now set to 100
    gpgme_key_t key[100];
#else
    gpgme_key_t key[enc_to_keyids.size()];
#endif
    int nrecipients;
    FB::variant recipient;
    FB::VariantList recpients;
    gpgme_encrypt_result_t enc_result;
    FB::VariantMap response;
    bool unusable_key = false;

    err = gpgme_data_new_from_mem (&in, data.c_str(), data.length(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_set_encoding(in, GPGME_DATA_ENCODING_ARMOR);
    if(err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_set_encoding(out, GPGME_DATA_ENCODING_ARMOR);
    if(err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    for (nrecipients=0; nrecipients < enc_to_keyids.size(); nrecipients++) {

        recipient = enc_to_keyids[nrecipients];

        err = gpgme_get_key (ctx, recipient.convert_cast<std::string>().c_str(), &key[nrecipients], 0);
        if(err != GPG_ERR_NO_ERROR)
            return get_error_map(__func__, gpgme_err_code (err),
                gpgme_strerror (err), __LINE__, __FILE__,
                recipient.convert_cast<std::string>().c_str());

        // Check if key is unusable/invalid
        unusable_key = key[nrecipients]->invalid? true :
            key[nrecipients]->expired? true :
            key[nrecipients]->revoked? true :
            key[nrecipients]->disabled? true : false;

        if (unusable_key) {
            // Somehow an ususable/invalid key has been passed to the method
            std::string keyid = key[nrecipients]->subkeys->fpr;

            std::string strerror = key[nrecipients]->invalid? "Invalid key" :
            key[nrecipients]->expired? "Key expired" :
            key[nrecipients]->revoked? "Key revoked" :
            key[nrecipients]->disabled? "Key disabled" : "Unknown error";

            err = key[nrecipients]->invalid? 53 :
            key[nrecipients]->expired? 153 :
            key[nrecipients]->revoked? 94 :
            key[nrecipients]->disabled? 53 : GPG_ERR_UNKNOWN_ERRNO;

            return get_error_map(__func__, gpgme_err_code (err), strerror, __LINE__, __FILE__, keyid);
        }

    }

    // NULL terminate the key array
    key[enc_to_keyids.size()] = NULL;

    if (sign) {
        if (enc_to_keyids.size() < 1) {
            // NOTE: This doesn't actually work due to an issue with gpgme-1.3.2.
            //  see: https://bugs.g10code.com/gnupg/issue1440 for details
            //err = gpgme_op_encrypt_sign (ctx, NULL, GPGME_ENCRYPT_NO_ENCRYPT_TO, in, out);
            return "Signed Symmetric Encryption is not yet implemented";
        } else {
            err = gpgme_op_encrypt_sign (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
        }
    } else {
        if (enc_to_keyids.size() < 1) {
            // Symmetric encrypt
            err = gpgme_op_encrypt (ctx, NULL, GPGME_ENCRYPT_NO_ENCRYPT_TO, in, out);
        } else {
            err = gpgme_op_encrypt (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
        }
    }

    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    if (enc_to_keyids.size() < 1) {
        // This was a symmetric operation, and gpgme_op_encrypt does not return
        //  an error if the passphrase is incorrect, so we need to check the
        //  returned value for actual substance.
        gpgme_data_seek(out, 0, SEEK_SET);
        char buf[513];
        gpgme_data_read (out, buf, 512);
        int buflen = strlen(buf);
        if (buflen < 52) {
            gpgme_release (ctx);
            gpgme_data_release (in);
            gpgme_data_release (out);
            FB::VariantMap error_map_obj;
            error_map_obj["error"] = true;
            error_map_obj["method"] = __func__;
            error_map_obj["gpg_error_code"] = "11";
            error_map_obj["error_string"] = "Passphrase did not match";
            error_map_obj["line"] = __LINE__;
            error_map_obj["file"] = __FILE__;
            return error_map_obj;
        }
    }

    enc_result = gpgme_op_encrypt_result (ctx);
    if (enc_result->invalid_recipients)
    {
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    }

    size_t out_size = 0;
    std::string out_buf;
    out_buf = gpgme_data_release_and_get_mem (out, &out_size);
    /* strip the size_t data out of the output buffer */
    out_buf = out_buf.substr(0, out_size);
    /* set the output object to NULL since it has
        already been released */
    out = NULL;

    /* if any of the gpgme objects have not yet
        been release, do so now */
    for (nrecipients=0; nrecipients < enc_to_keyids.size(); nrecipients++)
        gpgme_key_unref(key[nrecipients]);

    if (ctx)
        gpgme_release (ctx);
    if (in)
        gpgme_data_release (in);
    if (out)
        gpgme_data_release (out);

    response["data"] = out_buf;
    response["error"] = false;

    return response;
}

/*
    This method just calls webpgPlugin.gpgEncrypt without any keys
        as the parameter, which then uses Symmetric Encryption.
*/
/* This method accepts 2 parameters, data and sign [optional;
    default: 0:NULL:false].
    the return value is a string buffer of the result */
FB::variant webpgPluginAPI::gpgSymmetricEncrypt(const std::string& data,
        bool sign)
{
    FB::VariantList empty_keys;
    return webpgPluginAPI::gpgEncrypt(data, empty_keys, sign);
}

/* This method attempts to decrypt and verify the string <data>.
    If <use_agent> is 0, it will attempt to disable the key-agent
    to prevent a passphrase dialog from displaying. This would be
    useful in cases where it is useful when you want to verify or
    decrypt without unlocking the private keyring (i.e. in an
    automated parsing environment) */
FB::variant webpgPluginAPI::gpgDecryptVerify(const std::string& data, int use_agent)
{
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_decrypt_result_t decrypt_result;
    gpgme_verify_result_t verify_result;
    gpgme_signature_t sig;
    gpgme_data_t in, out;
    std::string out_buf;
    std::string envvar;
    FB::VariantMap response;
    int nsigs;
    int tnsigs = 0;
    char buf[513];
    int ret;

    char *agent_info = getenv("GPG_AGENT_INFO");

    if (use_agent == 0) {
        // Set the GPG_AGENT_INFO to null because the user shouldn't be bothered with for
        //  a passphrase if we get a chunk of encrypted data by mistake.
#ifdef HAVE_W32_SYSTEM
        setTempGPGOption("no-default-keyring", "");
        setTempGPGOption("secret-keyring", "/dev/null");
#else
        envvar = "GPG_AGENT_INFO=INVALID";
        putenv(strdup(envvar.c_str()));
#endif
    }

    ctx = get_gpgme_ctx();

    err = gpgme_data_new_from_mem (&in, data.c_str(), data.length(), 0);
    if (err != GPG_ERR_NO_ERROR) {
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    }

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR) {
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    }

    err = gpgme_op_decrypt_verify (ctx, in, out);

    decrypt_result = gpgme_op_decrypt_result (ctx);
    verify_result = gpgme_op_verify_result (ctx);

    if (use_agent == 0) {
#ifdef HAVE_W32_SYSTEM
        restoreGPGConfig();
#else
        // Restore GPG_AGENT_INFO to its original value
        envvar = "GPG_AGENT_INFO=";
        envvar += agent_info;
        putenv(strdup(envvar.c_str()));
#endif
    }

    if (err != GPG_ERR_NO_ERROR && !verify_result) {
        // There was an error returned while decrypting;
        //   either bad data, or signed only data
        if (verify_result && verify_result->signatures) {
            if (verify_result->signatures->status != GPG_ERR_NO_ERROR) {
                //No valid GPG data to decrypt or signatures to verify; possibly bad armor.\" }";
                return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
            }
        }
        if (gpg_err_code(err) == GPG_ERR_CANCELED) {
            return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
        }
        if (gpg_err_code(err) == GPG_ERR_BAD_PASSPHRASE) {
            return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
        }
        if (gpg_err_source(err) == GPG_ERR_SOURCE_PINENTRY) {
            return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
        }
        if (gpg_err_source(err) == GPG_ERR_SOURCE_GPGAGENT) {
            return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
        }
    }

    FB::VariantMap signatures;
    if (verify_result && verify_result->signatures) {
        tnsigs = 0;
        for (nsigs=0, sig=verify_result->signatures; sig; sig = sig->next, nsigs++) {
            FB::VariantMap signature;
            signature["fingerprint"] = nonnull (sig->fpr);
            signature["timestamp"] = sig->timestamp;
            signature["expiration"] = sig->exp_timestamp;
            signature["validity"] = sig->validity == GPGME_VALIDITY_UNKNOWN? "unknown":
                    sig->validity == GPGME_VALIDITY_UNDEFINED? "undefined":
                    sig->validity == GPGME_VALIDITY_NEVER? "never":
                    sig->validity == GPGME_VALIDITY_MARGINAL? "marginal":
                    sig->validity == GPGME_VALIDITY_FULL? "full":
                    sig->validity == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]";
            signature["status"] = gpg_err_code (sig->status) == GPG_ERR_NO_ERROR? "GOOD":
                    gpg_err_code (sig->status) == GPG_ERR_BAD_SIGNATURE? "BAD_SIG":
                    gpg_err_code (sig->status) == GPG_ERR_NO_PUBKEY? "NO_PUBKEY":
                    gpg_err_code (sig->status) == GPG_ERR_NO_DATA? "NO_SIGNATURE":
                    gpg_err_code (sig->status) == GPG_ERR_SIG_EXPIRED? "GOOD_EXPSIG":
                    gpg_err_code (sig->status) == GPG_ERR_KEY_EXPIRED? "GOOD_EXPKEY": "INVALID";
            signatures[i_to_str(nsigs)] = signature;
            tnsigs++;
        }
    }

    if (nsigs < 1 || err == 11) {
        response["message_type"] = "encrypted_message";
        if (use_agent == 0) {
            response["message_event"] = "auto";
        } else {
            response["message_event"] = "manual";
        }
    } else {
        response["message_type"] = "signed_message";
    }

    if (err != GPG_ERR_NO_ERROR && tnsigs < 1) {
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    }

    if (gpgme_err_code (err) == 58 && tnsigs < 1) {
        gpgme_data_release (out);
        response["data"] = data;
        response["message_type"] = "detached_signature";
    } else {
        ret = gpgme_data_seek(out, 0, SEEK_SET);

        if (ret)
            return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

        while ((ret = gpgme_data_read (out, buf, 512)) > 0)
            out_buf += buf;

        if (ret < 0)
            return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

        if (out_buf.length() < 1) {
            response["data"] = data;
            response["message_type"] = "detached_signature";
            gpgme_data_release (out);
        } else {
            size_t out_size = 0;
            gpgme_data_seek(out, 0, SEEK_SET);
            out_buf = gpgme_data_release_and_get_mem (out, &out_size);

            /* strip the size_t data out of the output buffer */
            out_buf = out_buf.substr(0, out_size);
            response["data"] = out_buf;
        }

    }

    response["signatures"] = signatures;
    response["error"] = false;
    gpgme_data_release (in);
    gpgme_release (ctx);

    return response;
}


FB::variant webpgPluginAPI::gpgDecrypt(const std::string& data)
{
    return webpgPluginAPI::gpgDecryptVerify(data, 1);
}

FB::variant webpgPluginAPI::gpgVerify(const std::string& data)
{
    return webpgPluginAPI::gpgDecryptVerify(data, 0);
}

/*
    This method signs the data plain_text with the keys found in signers, using the mode
        specified in sign_mode.

    sign_mode is one of:
        0: GPGME_SIG_MODE_NORMAL
        1: GPGME_SIG_MODE_DETACH
        2: GPGME_SIG_MODE_CLEAR

*/
FB::variant webpgPluginAPI::gpgSignText(const FB::VariantList& signers, const std::string& plain_text,
    int sign_mode)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t in, out;
    gpgme_key_t key;
    gpgme_sig_mode_t sig_mode;
    gpgme_sign_result_t sign_result;
    int nsigners;
    FB::variant signer;
    FB::VariantMap result;

    if (sign_mode == 0)
        sig_mode = GPGME_SIG_MODE_NORMAL;
    else if (sign_mode == 1)
        sig_mode = GPGME_SIG_MODE_DETACH;
    else if (sign_mode == 2)
        sig_mode = GPGME_SIG_MODE_CLEAR;

    for (nsigners=0; nsigners < signers.size(); nsigners++) {
        signer = signers[nsigners];
        err = gpgme_op_keylist_start (ctx, signer.convert_cast<std::string>().c_str(), 0);
        if (err != GPG_ERR_NO_ERROR)
            return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

        err = gpgme_op_keylist_next (ctx, &key);
        if (err != GPG_ERR_NO_ERROR)
            return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

        err = gpgme_op_keylist_end (ctx);
        if (err != GPG_ERR_NO_ERROR)
            return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

        err = gpgme_signers_add (ctx, key);
        if (err != GPG_ERR_NO_ERROR)
            return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

        gpgme_key_unref (key);

    }

    if (!nsigners > 0)
        return get_error_map(__func__, -1, "No signing keys found", __LINE__, __FILE__);

    err = gpgme_data_new_from_mem (&in, plain_text.c_str(), plain_text.length(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_sign(ctx, in, out, sig_mode);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    sign_result = gpgme_op_sign_result (ctx);

    if (!sign_result)
        return get_error_map(__func__,  gpgme_err_code (err), "The signed result is invalid", __LINE__, __FILE__);

    gpgme_data_seek(out, 0, SEEK_SET);

    size_t out_size = 0;
    std::string out_buf;
    out_buf = gpgme_data_release_and_get_mem (out, &out_size);
    /* strip the size_t data out of the output buffer */
    out_buf = out_buf.substr(0, out_size);
    /* set the output object to NULL since it has
        already been released */
    out = NULL;

    result["error"] = false;
    result["data"] = out_buf;

    gpgme_data_release (in);
    gpgme_release (ctx);

    return result;

}

FB::variant webpgPluginAPI::gpgSignUID(const std::string& keyid, long sign_uid,
    const std::string& with_keyid, long local_only, long trust_sign, 
    long trust_level)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap result;
    current_uid = i_to_str(sign_uid);

    /* set the default key to the with_keyid 
        gpgSetPreference returns the orginal value (if any) of
        the 'default-key' configuration parameter. We will put
        this into a variable so we can restore the setting when
        our UID Signing operation is complete (or failed)
    */

    /* collect the original value so we can restore when done */
    std::string original_value = get_preference("default-key");
    webpgPluginAPI::gpgSetPreference("default-key", 
        (char *) with_keyid.c_str());

    /* Release the context and create it again to catch the changes */
    gpgme_release (ctx);
    ctx = get_gpgme_ctx();
    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        result = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        result = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        result = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        result = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    edit_status = "gpgSignUID(keyid='" + keyid + "', sign_uid='" + i_to_str(sign_uid) + 
        "', with_keyid='" + with_keyid + "', local_only='" + i_to_str(local_only) + "', trust_sign='" + 
        i_to_str(trust_sign) + "', trust_level='" + i_to_str(trust_level) + "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_sign, out, out);
    if (err != GPG_ERR_NO_ERROR) {
        if (err == GPGME_STATUS_ALREADY_SIGNED) {
            result = get_error_map(__func__, err, "The selected UID has already been signed with this key.", __LINE__, __FILE__);
        } else if (err == GPGME_STATUS_KEYEXPIRED) {
            result =  get_error_map(__func__, err, "This key is expired; You cannot sign using an expired key.", __LINE__, __FILE__);
        } else if (err == GPGME_STATUS_SIGEXPIRED) {
            result =  get_error_map(__func__, err, "This key is expired; You cannot sign using an expired key.", __LINE__, __FILE__);
        } else {
            result = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
        }
    }

    /* if the original value was not empty, reset it to the previous value */
    if (strcmp ((char *) original_value.c_str(), "0")) {
        webpgPluginAPI::gpgSetPreference("default-key", original_value);
    }

    FB::VariantMap response;
    response["error"] = false;
    response["result"] = "success";

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    if (result.size())
        return result;

    return response;
}

FB::variant webpgPluginAPI::gpgEnableKey(const std::string& keyid)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap response;

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    edit_status = "gpgEnableKey(keyid='" + keyid + "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_enable, out, out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    response["error"] = false;
    response["result"] = "key enabled";

    return response;
}

FB::variant webpgPluginAPI::gpgDisableKey(const std::string& keyid)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap response;

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    edit_status = "gpgDisableKey(keyid='" + keyid + "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_disable, out, out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    response["error"] = false;
    response["result"] = "key disabled";

    return response;

}


FB::variant webpgPluginAPI::gpgDeleteUIDSign(const std::string& keyid,
    long uid, long signature)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap response;

    current_uid = i_to_str(uid);
    current_sig = i_to_str(signature);

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    edit_status = "gpgDeleteUIDSign(keyid='" + keyid + "', uid='" + i_to_str(uid) + "', signature='" + 
        i_to_str(signature) + "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_delsign, out, out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    current_uid = "0";
    current_sig = "0";

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    response["error"] = false;
    response["result"] = "signature deleted";

    return response;
}

void webpgPluginAPI::progress_cb(void *self, const char *what, int type, int current, int total)
{
    if (!strcmp (what, "primegen") && !current && !total
        && (type == '.' || type == '+' || type == '!'
        || type == '^' || type == '<' || type == '>')) {
        webpgPluginAPI* API = (webpgPluginAPI*) self;
        API->FireEvent("onkeygenprogress", FB::variant_list_of(type));
    }
    if (!strcmp (what, "complete")) {
        webpgPluginAPI* API = (webpgPluginAPI*) self;
        API->FireEvent("onkeygencomplete", FB::variant_list_of("complete"));
    }
}

std::string webpgPluginAPI::gpgGenKeyWorker(const std::string& key_type, const std::string& key_length, 
        const std::string& subkey_type, const std::string& subkey_length, const std::string& name_real, 
        const std::string& name_comment, const std::string& name_email, const std::string& expire_date, 
        const std::string& passphrase, void* APIObj,
        void(*cb_status)(
            void *self,
            const char *what,
            int type,
            int current,
            int total
        )
    )
{

    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    std::string params = "<GnupgKeyParms format=\"internal\">\n"
        "Key-Type: " + key_type + "\n"
        "Key-Length: " + key_length + "\n"
        "Subkey-Type: " + subkey_type + "\n"
        "Subkey-Length: " + subkey_length + "\n"
        "Name-Real: " + name_real + "\n";
    if (name_comment.length() > 0) {
        params += "Name-Comment: " + name_comment + "\n";
    }
    if (name_email.length() > 0) {
        params += "Name-Email: " + name_email + "\n";
    }
    if (expire_date.length() > 0) {
        params += "Expire-Date: " + expire_date + "\n";
    } else {
        params += "Expire-Date: 0\n";
    }
    if (passphrase.length() > 0) {
        params += "Passphrase: " + passphrase + "\n";
    }
    params += "</GnupgKeyParms>\n";
    const char *parms = params.c_str();

    gpgme_genkey_result_t result;

    gpgme_set_progress_cb (ctx, cb_status, APIObj);

    err = gpgme_op_genkey (ctx, parms, NULL, NULL);
    if (err)
        return "Error with genkey start" + err;

    result = gpgme_op_genkey_result (ctx);

    if (!result)
    {
#ifdef DEBUG
        fprintf (stderr, "%s:%d: gpgme_op_genkey_result returns NULL\n",
           __FILE__, __LINE__);
#endif
        return "error with result";
    }

#ifdef DEBUG
    printf ("Generated key: %s (%s)\n", result->fpr ? result->fpr : "none",
        result->primary ? (result->sub ? "primary, sub" : "primary")
        : (result->sub ? "sub" : "none"));
#endif

    gpgme_release (ctx);
    const char* status = (char *) "complete";
    cb_status(APIObj, status, 33, 33, 33);
    return "done";
}

FB::variant webpgPluginAPI::gpgGenSubKeyWorker(const std::string& keyid, const std::string& subkey_type,
        const std::string& subkey_length, const std::string& subkey_expire, bool sign_flag,
        bool enc_flag, bool auth_flag, void* APIObj,
        void(*cb_status)(
            void *self,
            const char *what,
            int type,
            int current,
            int total
        )
    )
{

    // Set the option expert so we can access all of the subkey types
    setTempGPGOption("expert", "");

    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap response;

    gen_subkey_type = subkey_type;
    gen_subkey_length = subkey_length;
    gen_subkey_expire = subkey_expire;
    gen_sign_flag = sign_flag;
    gen_enc_flag = enc_flag;
    gen_auth_flag = auth_flag;

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_set_progress_cb (ctx, cb_status, APIObj);

    edit_status = "gpgGenSubKeyWorker(keyid='" + keyid + "', subkey_type='" + subkey_type + 
        "', subkey_length='" + subkey_length + "', subkey_expire='" + subkey_expire + "', sign_flag='" + 
        i_to_str(sign_flag) + "', enc_flag='" + i_to_str(enc_flag) + "', auth_flag='" + 
        i_to_str(auth_flag) + "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_add_subkey, out, out);

    if (err != GPG_ERR_NO_ERROR) {
        if (gpg_err_code(err) == GPG_ERR_CANCELED)
            this->FireEvent("onkeygencomplete", FB::variant_list_of("failed: cancelled"));
        else if (gpg_err_code(err) == GPG_ERR_BAD_PASSPHRASE)
            this->FireEvent("onkeygencomplete", FB::variant_list_of("failed: bad passphrase"));

        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    }

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    // Restore the options to normal
    restoreGPGConfig();

    const char* status = (char *) "complete";
    cb_status(APIObj, status, 33, 33, 33);
    return "done";
}

void webpgPluginAPI::threaded_gpgGenKey(genKeyParams params)
{
    std::string result = webpgPluginAPI::gpgGenKeyWorker(params.key_type, params.key_length,
        params.subkey_type, params.subkey_length, params.name_real,
        params.name_comment, params.name_email, params.expire_date,
        params.passphrase, this, &webpgPluginAPI::progress_cb
    );

}

void webpgPluginAPI::threaded_gpgGenSubKey(genSubKeyParams params)
{
    FB::variant result = webpgPluginAPI::gpgGenSubKeyWorker(params.keyid, params.subkey_type,
        params.subkey_length, params.subkey_expire, params.sign_flag, params.enc_flag,
        params.auth_flag, this, &webpgPluginAPI::progress_cb
    );

}

std::string webpgPluginAPI::gpgGenKey(const std::string& key_type, 
        const std::string& key_length, const std::string& subkey_type, 
        const std::string& subkey_length, const std::string& name_real,
        const std::string& name_comment, const std::string& name_email, 
        const std::string& expire_date, const std::string& passphrase)
{

    genKeyParams params;

    params.key_type = key_type;
    params.key_length = key_length;
    params.subkey_type = subkey_type;
    params.subkey_length = subkey_length;
    params.name_real = name_real;
    params.name_comment = name_comment;
    params.name_email = name_email;
    params.expire_date = expire_date;
    params.passphrase = passphrase;

    boost::thread genkey_thread(
        boost::bind(
            &webpgPluginAPI::genKeyThreadCaller,
            this, params)
    );

    return "queued";
}

FB::variant webpgPluginAPI::gpgImportKey(const std::string& ascii_key)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t key_buf;
    gpgme_import_result_t result;

    err = gpgme_data_new_from_mem (&key_buf, ascii_key.c_str(), ascii_key.length(), 1);

    err = gpgme_op_import (ctx, key_buf);

    result = gpgme_op_import_result (ctx);
    gpgme_data_release (key_buf);

    FB::VariantMap status;

    status["considered"] = result->considered;
    status["no_user_id"] = result->no_user_id;
    status["imported"] = result->imported;
    status["imported_rsa"] = result->imported_rsa;
    status["new_user_ids"] = result->new_user_ids;
    status["new_sub_keys"] = result->new_sub_keys;
    status["new_signatures"] = result->new_signatures;
    status["new_revocations"] = result->new_revocations;
    status["secret_read"] = result->secret_read;
    status["secret_imported"] = result->secret_imported;
    status["secret_unchanged"] = result->secret_unchanged;
    status["not_imported"] = result->not_imported;

    FB::VariantMap imports_map;
    int nimports = 0;
    gpgme_import_status_t import;
    for (nimports=0, import=result->imports; import; import = import->next, nimports++) {
        FB::VariantMap import_item_map;
        import_item_map["fingerprint"] = nonnull (import->fpr);
        import_item_map["result"] = gpgme_strerror(import->result);
        import_item_map["status"] = import->status;
        import_item_map["new_key"] = import->status & GPGME_IMPORT_NEW? true : false;
        import_item_map["new_uid"] = import->status & GPGME_IMPORT_UID? true : false;
        import_item_map["new_sig"] = import->status & GPGME_IMPORT_SIG? true : false;
        import_item_map["new_subkey"] = import->status & GPGME_IMPORT_SUBKEY? true : false;
        import_item_map["new_secret"] = import->status & GPGME_IMPORT_SECRET? true : false;
		imports_map[i_to_str(nimports)] = import_item_map;
	}
    status["imports"] = imports_map;
    gpgme_release (ctx);

    return status;
}

FB::variant webpgPluginAPI::gpgDeleteKey(const std::string& keyid, int allow_secret)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_key_t key = NULL;
    FB::VariantMap response;

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_delete(ctx, key, allow_secret);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_key_unref (key);
    gpgme_release (ctx);

    response["error"] = false;
    response["result"] = "Key deleted";

    return response;
}

/*
    This method executes webpgPlugin.gpgDeleteKey with the allow_secret=0,
        which allows it to only delete public Public Keys from the keyring.
*/

FB::variant webpgPluginAPI::gpgDeletePublicKey(const std::string& keyid)
{
    return webpgPluginAPI::gpgDeleteKey(keyid, 0);
}

/*
    This method executes webpgPlugin.gpgDeleteKey with the allow_secret=1,
        which allows it to delete Private and Public Keys from the keyring.
*/

FB::variant webpgPluginAPI::gpgDeletePrivateKey(const std::string& keyid)
{
    return webpgPluginAPI::gpgDeleteKey(keyid, 1);
}

FB::variant webpgPluginAPI::gpgDeletePrivateSubKey(const std::string& keyid, int key_idx)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap response;

    key_index = i_to_str(key_idx);

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    edit_status = "gpgDeletePrivateSubkey(keyid='" + keyid + "', key_idx='" + i_to_str(key_idx) +
        "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_delete_subkey, out, out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);


    key_index = "";

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    response["error"] = false;
    response["edit_status"] = edit_status;
    response["result"] = "Subkey Delete";

    return response;
}

FB::variant webpgPluginAPI::gpgGenSubKey(const std::string& keyid, 
        const std::string& subkey_type, const std::string& subkey_length,
        const std::string& subkey_expire, bool sign_flag, bool enc_flag, bool auth_flag)
{

    genSubKeyParams params;

    params.keyid = keyid;
    params.subkey_type = subkey_type;
    params.subkey_length = subkey_length;
    params.subkey_expire = subkey_expire;
    params.sign_flag = sign_flag;
    params.enc_flag = enc_flag;
    params.auth_flag = auth_flag;

    boost::thread genkey_thread(
        boost::bind(
            &webpgPluginAPI::genSubKeyThreadCaller,
            this, params)
    );

    return "queued";
}

FB::variant webpgPluginAPI::gpgSetKeyTrust(const std::string& keyid, long trust_level)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap response;
    trust_assignment = i_to_str(trust_level);

    if (trust_level < 1) {
        response["error"] = true;
        response["result"] = "Valid trust assignment values are 1 through 5";
        return response;
    }

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    edit_status = "gpgSetKeyTrust(keyid='" + keyid + "', trust_level='" + i_to_str(trust_level) + "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_assign_trust, out, out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    trust_assignment = "0";

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    response["error"] = false;
    response["result"] = "trust value assigned";

    return response;
}

FB::variant webpgPluginAPI::gpgAddUID(const std::string& keyid, const std::string& name,
        const std::string& email, const std::string& comment)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap response;
    genuid_name = name;
    genuid_email = email;
    genuid_comment = comment;

    if (isdigit(name.c_str()[0])) {
        response["error"] = true;
        response["result"] = "UID names cannot start with a digit...";
        return response;
    }

    if (strlen (name.c_str()) < 5) {
        response["error"] = true;
        response["result"] = "UID's must be at least 5 chars long...";
        return response;
    }

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    edit_status = "gpgAddUID(keyid='" + keyid + "', name='" + name + "', email='" + email + 
        "', comment='" + comment + "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_add_uid, out, out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    response["name"] = genuid_name;
    response["email"] = genuid_email;
    response["comment"] = genuid_comment;

    genuid_name = "";
    genuid_email = "";
    genuid_comment = "";

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    response["error"] = false;
    response["edit_status"] = edit_status;
    response["result"] = "UID added";

    return response;
}

FB::variant webpgPluginAPI::gpgDeleteUID(const std::string& keyid, long uid_idx)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap response;

    if (uid_idx < 1) {
        response["error"] = true;
        response["result"] = "UID index is always above zero, something is amiss...";
        return response;
    }

    current_uid = i_to_str(uid_idx);

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    edit_status = "gpgDeleteUID(keyid='" + keyid + "', uid_idx='" + i_to_str(uid_idx) + "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_delete_uid, out, out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);


    current_uid = "0";

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    response["error"] = false;
    response["edit_status"] = edit_status;
    response["result"] = "UID deleted";

    return response;
}

FB::variant webpgPluginAPI::gpgSetPrimaryUID(const std::string& keyid, long uid_idx)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap response;

    if (uid_idx < 1) {
        response["error"] = true;
        response["result"] = "UID index is always above zero, something is amiss...";
        return response;
    }

    current_uid = i_to_str(uid_idx);

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    edit_status = "gpgSetPrimaryUID(keyid='" + keyid + "', uid_idx='" + i_to_str(uid_idx) + "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_set_primary_uid, out, out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);


    current_uid = "0";

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    response["error"] = false;
    response["edit_status"] = edit_status;
    response["result"] = "Primary UID changed";

    return response;
}

FB::variant webpgPluginAPI::gpgSetKeyExpire(const std::string& keyid, long key_idx, long expire)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap response;

    key_index = i_to_str(key_idx);
    expiration = i_to_str(expire);

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    edit_status = "gpgSetKeyExpire(keyid='" + keyid + "', key_idx='" + i_to_str(key_idx) + 
        "', expire='" + i_to_str(expire) + "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_set_key_expire, out, out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);


    key_index = "";
    expiration = "";

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    response["error"] = false;
    response["edit_status"] = edit_status;
    response["result"] = "Expiration changed";

    return response;
}

FB::variant webpgPluginAPI::gpgSetPubkeyExpire(const std::string& keyid, long expire)
{
    return webpgPluginAPI::gpgSetKeyExpire(keyid, 0, expire);
}


FB::variant webpgPluginAPI::gpgSetSubkeyExpire(const std::string& keyid, long key_idx, long expire)
{
    return webpgPluginAPI::gpgSetKeyExpire(keyid, key_idx, expire);
}

FB::variant webpgPluginAPI::gpgExportPublicKey(const std::string& keyid)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    FB::variant keydata;
    FB::VariantMap response;

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_export (ctx, keyid.c_str(), 0, out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_data_seek(out, 0, SEEK_SET);

    size_t out_size = 0;
    std::string out_buf;
    out_buf = gpgme_data_release_and_get_mem (out, &out_size);
    /* strip the size_t data out of the output buffer */
    out_buf = out_buf.substr(0, out_size);
    /* set the output object to NULL since it has
        already been released */
    out = NULL;

    gpgme_release (ctx);

    response["error"] = false;
    response["result"] = out_buf;

    return response;
}

FB::variant webpgPluginAPI::gpgRevokeItem(const std::string& keyid, const std::string& item, int key_idx,
    int uid_idx, int sig_idx, int reason, const std::string& desc)
{

    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap response;

    key_index = i_to_str(key_idx);
    current_uid = i_to_str(uid_idx);
    current_sig = i_to_str(sig_idx);
    revitem = item.c_str();
    reason_index = i_to_str(reason);
    description = desc.c_str();


    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    edit_status = "gpgRevokeItem(keyid='" + keyid + "', item='" + item + "', key_idx='" + 
        i_to_str(key_idx) + "', uid_idx='" + i_to_str(uid_idx) + "', sig_idx='" + i_to_str(sig_idx) +
        "', reason='" + i_to_str(reason) + "', desc='" + desc + "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_revoke_item, out, out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);


    key_index = "";
    reason_index = "";
    current_uid = "";

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    response["error"] = false;
    response["edit_status"] = edit_status;
    response["result"] = "Item Revoked";

    return response;
}

FB::variant webpgPluginAPI::gpgRevokeKey(const std::string& keyid, int key_idx, int reason,
    const std::string &desc)
{
    return webpgPluginAPI::gpgRevokeItem(keyid, "revkey", key_idx, 0, 0, reason, desc);
}

FB::variant webpgPluginAPI::gpgRevokeUID(const std::string& keyid, int uid_idx, int reason,
    const std::string &desc)
{
    return webpgPluginAPI::gpgRevokeItem(keyid, "revuid", 0, uid_idx, 0, reason, desc);
}

FB::variant webpgPluginAPI::gpgRevokeSignature(const std::string& keyid, int uid_idx, int sig_idx,
    int reason, const std::string &desc)
{
    return webpgPluginAPI::gpgRevokeItem(keyid, "revsig", 0, uid_idx, sig_idx, reason, desc);
}

FB::variant webpgPluginAPI::gpgChangePassphrase(const std::string& keyid)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    FB::VariantMap result;

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        result = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        result = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        result = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        result = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    edit_status = "gpgChangePassphrase(keyid='" + keyid + "');\n";
    err = gpgme_op_edit (ctx, key, edit_fnc_change_passphrase, out, out);
    if (err != GPG_ERR_NO_ERROR)
        result = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    FB::VariantMap response;
    if (!key->secret) {
        response["error"] = true;
        response["result"] = "no secret";
    } else {
        response["error"] = false;
        response["result"] = "success";
    }

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);

    if (result.size())
        return result;

    return response;
}

// Read-only property version
std::string webpgPluginAPI::get_version()
{
    return FBSTRING_PLUGIN_VERSION;
}

