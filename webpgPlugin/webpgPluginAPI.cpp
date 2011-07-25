/**********************************************************\

  Auto-generated webpgPluginAPI.cpp

\**********************************************************/

#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"

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
                        int line, const std::string& file){
    FB::VariantMap error_map_obj;
    error_map_obj["error"] = true;
    error_map_obj["method"] = method;
    error_map_obj["gpg_error_code"] = gpg_error_code;
    error_map_obj["error_string"] = error_string;
    error_map_obj["line"] = line;
    error_map_obj["file"] = file;
    return error_map_obj;
}

/* An inline method to convert a null char */
inline
static const char *
    nonnull (const char *s)
    {
      return s? s :"[none]";
    }

/* An inline method to convert an integer to a string */
inline
std::string i_to_str(const int &number)
{
   std::ostringstream oss;
   oss << number;
   return oss.str();
}

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
    registerMethod("getPublicKeyList", make_method(this, &webpgPluginAPI::getPublicKeyList));
    registerMethod("getPrivateKeyList", make_method(this, &webpgPluginAPI::getPrivateKeyList));
    registerMethod("getNamedKey", make_method(this, &webpgPluginAPI::getNamedKey));
    registerMethod("gpgEncrypt", make_method(this, &webpgPluginAPI::gpgEncrypt));
    registerMethod("gpgDecrypt", make_method(this, &webpgPluginAPI::gpgDecrypt));
    registerMethod("gpgSignUID", make_method(this, &webpgPluginAPI::gpgSignUID));
    registerMethod("gpgEnableKey", make_method(this, &webpgPluginAPI::gpgEnableKey));
    registerMethod("gpgDisableKey", make_method(this, &webpgPluginAPI::gpgDisableKey));
    registerMethod("gpgDeleteUIDSign", make_method(this, &webpgPluginAPI::gpgDeleteUIDSign));
    registerMethod("gpgGenKey", make_method(this, &webpgPluginAPI::gpgGenKey));
    registerMethod("gpgImportKey", make_method(this, &webpgPluginAPI::gpgImportKey));

    registerEvent("onkeygenprogress");
    registerEvent("onkeygencomplete");

    // Read-only property
    registerProperty("version",
                     make_property(this,
                        &webpgPluginAPI::get_version));
    // FIXME: This is set on init and never refreshed - however the values may change during runtime
    registerProperty("gpg_status",
                    make_property(this,
                        &webpgPluginAPI::get_gpg_status));

    // FIXME: This is set on init and never refreshed - however the value may change during runtime
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

void webpgPluginAPI::init(){
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    FB::VariantMap error_map;
    FB::VariantMap response;

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
    if (err != GPG_ERR_NO_ERROR){
        error_map = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    }

    err = gpgme_new (&ctx);
    if (err != GPG_ERR_NO_ERROR)
        error_map = get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    if (ctx)
        gpgme_release (ctx);

    char *gpg_agent_info = getenv("GPG_AGENT_INFO");

    if (error_map.size()) {
        //response = error_map;
        response["gpgme_valid"] = false;
    } else {
        response["error"] = false;
        response["gpgme_valid"] = true;
    }

    if (gpg_agent_info != NULL) {
        response["gpg_agent_info"] = gpg_agent_info;
    } else {
        response["gpg_agent_info"] = "unknown";
    }

    response["gpgconf_detected"] = gpgconf_detected();
    response["gpgme_version"] = gpgme_version;

    webpgPluginAPI::gpg_status_map = response;
};

gpgme_ctx_t webpgPluginAPI::get_gpgme_ctx(){
    gpgme_ctx_t ctx;
    gpgme_error_t err;

    setlocale (LC_ALL, "");
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
    #ifdef LC_MESSAGES
        gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
    #endif

    err = gpgme_new (&ctx);
    gpgme_set_textmode (ctx, 1);
    gpgme_set_armor (ctx, 1);

    return ctx;
}

//std::string webpgPluginAPI::get_gpgme_version(){
//    return webpgPluginAPI::_gpgme_version;
//}

FB::VariantMap webpgPluginAPI::get_gpg_status(){
    return webpgPluginAPI::gpg_status_map;
}

/*
    This method retrieves all keys matching name, or if name is left empty,
        returns all keys in the keyring.
    NOTE: This method is not exposed to the NPAPI plugin, it is only called internally
*/
FB::VariantMap webpgPluginAPI::getKeyList(const std::string& name, int secret_only){
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
        //keylist_map["error"] = "error: 2; Problem with protocol type";

    /* apply the keylist mode to the context and set
        the keylist_mode 
        NOTE: The keylist mode flag GPGME_KEYLIST_MODE_SIGS 
            returns the signatures of UIDS with the key */
    gpgme_set_keylist_mode (ctx, (gpgme_get_keylist_mode (ctx)
                                | GPGME_KEYLIST_MODE_VALIDATE 
                                | GPGME_KEYLIST_MODE_SIGS));

    /* gpgme_op_keylist_start (gpgme_ctx_t ctx, const char *pattern, int secret_only) */
    if (name.length() > 0){ // limit key listing to search criteria 'name'
        err = gpgme_op_keylist_start (ctx, name.c_str(), 0);
    } else { // list all keys
        err = gpgme_op_keylist_ext_start (ctx, NULL, secret_only, 0);
    }
    if(err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
        //return keylist_map["error"] = "error: 3; Problem with keylist_start";

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
                signatures_map[i_to_str(nsigs)] = nonnull (sig->keyid);
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
        //return keylist_map["error"] = "error: 4; Key listing unexpectedly truncated";
     }
    gpgme_release (ctx);
    return keylist_map;
}

/*
    This method executes webpgPlugin.getKeyList with an empty string and
        secret_only=0 which returns all Public Keys in the keyring.
*/

FB::VariantMap webpgPluginAPI::getPublicKeyList(){
    return webpgPluginAPI::getKeyList("", 0);
}

/*
    This method executes webpgPlugin.getKeyList with an empty string and
        secret_only=1 which returns all keys in the keyring which
        the user has the corrisponding secret key.
*/

FB::VariantMap webpgPluginAPI::getPrivateKeyList(){
    return webpgPluginAPI::getKeyList("", 1);
}

/* 
    This method just calls webpgPlugin.getKeyList with a name/email
        as the parameter
*/
FB::VariantMap webpgPluginAPI::getNamedKey(const std::string& name){
    return webpgPluginAPI::getKeyList(name, 0);
}

bool webpgPluginAPI::gpgconf_detected() {
    gpgme_error_t err;
    std::string cfg_present;
    err = gpgme_engine_check_version (GPGME_PROTOCOL_GPGCONF);
    if (err != GPG_ERR_NO_ERROR) {
        return false;
    }
    return true;
}

std::string webpgPluginAPI::get_preference(const std::string& preference) {
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_conf_comp_t conf, comp;
    gpgme_conf_opt_t opt;
    std::string return_value;

    err = gpgme_engine_check_version (GPGME_PROTOCOL_GPGCONF);

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

FB::variant webpgPluginAPI::set_preference(const std::string& preference, const std::string& pref_value) {
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

    err = gpgme_conf_arg_new (&arg, GPGME_CONF_STRING, (char *) pref_value.c_str());

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

        if (opt->value) {
            original_arg = opt->value;
        } else {
            original_arg = opt->value;
            return_code = "blank";
        }

        /* if the new argument and original argument are the same, return 0, 
            there is nothing to do. */
        if (original_arg && !strcmp (original_arg->value.string, arg->value.string)) {
            return "0";
        }

        if (opt) {
            if (!strcmp(pref_value.c_str(), "blank"))
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

    gpgme_conf_release (conf);

    if (!return_code.length())
        return_code = original_arg->value.string;

    return return_code;
}


/*
    This method passes a string to encrypt, a key to encrypt to and an
        optional key to encrypt from and calls webpgPlugin.gpgEncrypt.
        This method returns a string of the encrypted data.
*/
/* This method accepts 4 parameters, data, enc_to_keyid, 
    enc_from_keyid [optional], and sign [optional; default: 0:NULL:false]
    the return value is a string buffer of the result */
/* NOTE: Normally, we should call this without a value for
    encrypt_from_key to keep the anonymity of the user until after the 
    host has been validated */
FB::variant webpgPluginAPI::gpgEncrypt(const std::string& data, 
        const std::string& enc_to_keyid, const std::string& enc_from_keyid,
        const std::string& sign)
{
    /* declare variables */
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t in, out;
    gpgme_key_t key[3] = { NULL, NULL, NULL };
    gpgme_encrypt_result_t enc_result;
    FB::VariantMap response;

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

    err = gpgme_get_key (ctx, enc_to_keyid.c_str(),
           &key[0], 0);
    if(err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    if (enc_from_keyid.length()) {
        err = gpgme_get_key (ctx, enc_from_keyid.c_str(),
               &key[1], 0);
        if (err != GPG_ERR_NO_ERROR)
            return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    }

    err = gpgme_op_encrypt (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_data_seek(in, 0, SEEK_SET);
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
    gpgme_key_unref (key[0]);
    gpgme_key_unref (key[1]);
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

FB::variant webpgPluginAPI::gpgDecrypt(const std::string& data)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_decrypt_result_t decrypt_result;
    gpgme_verify_result_t verify_result;
    gpgme_signature_t sig;
    gpgme_data_t in, out;
    std::string out_buf;
    FB::VariantMap response;
    char *agent_info;
    int nsigs;

    agent_info = getenv("GPG_AGENT_INFO");

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

    if (err != GPG_ERR_NO_ERROR) {
        // There was an error returned while decrypting;
        //   either bad data, or signed only data
        if (verify_result->signatures) {
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

    size_t out_size = 0;
    out_buf = gpgme_data_release_and_get_mem (out, &out_size);
    /* strip the size_t data out of the output buffer */
    out_buf = out_buf.substr(0, out_size);
    response["data"] = out_buf;

    /* set the output object to NULL since it has
        already been released */
    out = NULL;
    out_buf = "";

    FB::VariantMap signatures;
    if (verify_result->signatures) {
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
        }
    }
    response["signatures"] = signatures;
    response["error"] = false;
    gpgme_data_release (in);
    gpgme_release (ctx);

    return response;
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
        set_preferences returns the orginal value (if any) of
        the 'default-key' configuration parameter. We will put
        this into a variable so we can restore the setting when
        our UID Signing operation is complete (or failed)
    */

    /* collect the original value so we can restore when done */
    std::string original_value = get_preference("default-key");
    webpgPluginAPI::set_preference("default-key", 
        (char *) with_keyid.c_str());

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

    step = 0;
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
        webpgPluginAPI::set_preference("default-key", original_value);
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
    long uid, long signature) {
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
    ) {

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

void webpgPluginAPI::threaded_gpgGenKey(genKeyParams params)
{
    std::string result = webpgPluginAPI::gpgGenKeyWorker(params.key_type, params.key_length,
        params.subkey_type, params.subkey_length, params.name_real,
        params.name_comment, params.name_email, params.expire_date,
        params.passphrase, this, &webpgPluginAPI::progress_cb
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
            &webpgPluginAPI::threadCaller,
            this, params)
    );

    return "queued";
}

FB::variant webpgPluginAPI::gpgImportKey(const std::string& ascii_key) {
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

// Read-only property version
std::string webpgPluginAPI::get_version()
{
    return "0.1.0b";
}

