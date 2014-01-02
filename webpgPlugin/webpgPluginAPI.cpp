/**********************************************************\
Original Author: Kyle L. Huff (kylehuff)

Created:    Jan 14, 2011
License:    GNU General Public License, version 2
            http://www.gnu.org/licenses/gpl-2.0.html

Copyright 2011 Kyle L. Huff, CURETHEITCH development team
\**********************************************************/

#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"
#include "DOM/Window.h"
#include "global/config.h"

#include "webpgPluginAPI.h"
#include <boost/make_shared.hpp>

#ifdef HAVE_W32_SYSTEM
#define __func__ __FUNCTION__
#endif

using namespace std;
using namespace mimetic;

///////////////////////////////////////////////////////////////////////////////
/// @fn webpgPluginAPI::webpgPluginAPI(const webpgPluginPtr& plugin,
///                                    const FB::BrowserHostPtr host)
///
/// @brief  Constructor for the JSAPI object.  Registers methods, properties,
///         and events that are accessible to Javascript.
///
/// @see FB::JSAPIAuto::registerMethod
/// @see FB::JSAPIAuto::registerProperty
/// @see FB::JSAPIAuto::registerEvent
///
/// @note if _EXTENSIONIZE is ture/nonnull, the plugin will only register the
///         provided methods if the plugin was loaded from a page at URL
///         "chrome://" (Mozilla products), "chrome-extension://" (Google
///         Chrome/Chromium), "widget://" (Opera) or "safari-extension://" to
///         prevent the plugin from being loaded by a public web page.
///         This flag is set at compile time, and cannot be modified during
///         operation.
///////////////////////////////////////////////////////////////////////////////
webpgPluginAPI::webpgPluginAPI(const webpgPluginPtr& plugin,
                               const FB::BrowserHostPtr& host)
                                    : m_plugin(plugin), m_host(host)
{
  static bool allow_op = true;
#ifdef _EXTENSIONIZE
  std::string location = m_host->getDOMWindow()->getLocation();
  size_t firefox_ext = location.find("chrome://");
  size_t chrome_ext = location.find("chrome-extension://");
  size_t opera_ext = location.find("widget://");
  size_t safari_ext = location.find("safari-extension://");
  if (chrome_ext != std::string::npos ||
      firefox_ext != std::string::npos ||
      opera_ext != std::string::npos ||
      safari_ext != std::string::npos)
      allow_op = true;
  else
      allow_op = false;
#endif

  if (allow_op == true) {
    registerMethod("getPublicKeyList",
      make_method(this, &webpgPluginAPI::getPublicKeyList)
    );
    registerMethod("getPrivateKeyList",
      make_method(this, &webpgPluginAPI::getPrivateKeyList)
    );
    registerMethod("getNamedKey",
      make_method(this, &webpgPluginAPI::getNamedKey)
    );
    registerMethod("getExternalKey",
      make_method(this, &webpgPluginAPI::getExternalKey)
    );
    registerMethod("gpgSetPreference",
      make_method(this, &webpgPluginAPI::gpgSetPreference)
    );
    registerMethod("gpgGetPreference",
      make_method(this, &webpgPluginAPI::gpgGetPreference)
    );
    registerMethod("gpgSetGroup",
      make_method(this, &webpgPluginAPI::gpgSetGroup)
    );
    registerMethod("gpgSetHomeDir",
      make_method(this, &webpgPluginAPI::gpgSetHomeDir)
    );
    registerMethod("gpgGetHomeDir",
      make_method(this, &webpgPluginAPI::gpgGetHomeDir)
    );
    registerMethod("gpgSetBinary",
      make_method(this, &webpgPluginAPI::gpgSetBinary)
    );
    registerMethod("gpgGetBinary",
      make_method(this, &webpgPluginAPI::gpgGetBinary)
    );
    registerMethod("gpgSetGPGConf",
      make_method(this, &webpgPluginAPI::gpgSetGPGConf)
    );
    registerMethod("gpgGetGPGConf",
      make_method(this, &webpgPluginAPI::gpgGetGPGConf));
    registerMethod("gpgEncrypt",
      make_method(this, &webpgPluginAPI::gpgEncrypt)
    );
    registerMethod("gpgSymmetricEncrypt",
      make_method(this, &webpgPluginAPI::gpgSymmetricEncrypt)
    );
    registerMethod("gpgDecrypt",
      make_method(this, &webpgPluginAPI::gpgDecrypt)
    );
    registerMethod("gpgVerify",
      make_method(this, &webpgPluginAPI::gpgVerify)
    );
    registerMethod("gpgSignText",
      make_method(this, &webpgPluginAPI::gpgSignText)
    );
    registerMethod("gpgSignUID",
      make_method(this, &webpgPluginAPI::gpgSignUID)
    );
    registerMethod("gpgDeleteUIDSign",
      make_method(this, &webpgPluginAPI::gpgDeleteUIDSign)
    );
    registerMethod("gpgEnableKey",
      make_method(this, &webpgPluginAPI::gpgEnableKey)
    );
    registerMethod("gpgDisableKey",
      make_method(this, &webpgPluginAPI::gpgDisableKey)
    );
    registerMethod("gpgGenKey",
      make_method(this, &webpgPluginAPI::gpgGenKey)
    );
    registerMethod("gpgGenSubKey",
      make_method(this, &webpgPluginAPI::gpgGenSubKey)
    );
    registerMethod("gpgImportKey",
      make_method(this, &webpgPluginAPI::gpgImportKey)
    );
    registerMethod("gpgImportExternalKey",
      make_method(this, &webpgPluginAPI::gpgImportExternalKey)
    );
    registerMethod("gpgDeletePublicKey",
      make_method(this, &webpgPluginAPI::gpgDeletePublicKey)
    );
    registerMethod("gpgDeletePrivateKey",
      make_method(this, &webpgPluginAPI::gpgDeletePrivateKey)
    );
    registerMethod("gpgDeletePrivateSubKey",
      make_method(this, &webpgPluginAPI::gpgDeletePrivateSubKey)
    );
    registerMethod("gpgSetKeyTrust",
      make_method(this, &webpgPluginAPI::gpgSetKeyTrust)
    );
    registerMethod("gpgAddUID",
      make_method(this, &webpgPluginAPI::gpgAddUID)
    );
    registerMethod("gpgDeleteUID",
      make_method(this, &webpgPluginAPI::gpgDeleteUID)
    );
    registerMethod("gpgSetPrimaryUID",
      make_method(this, &webpgPluginAPI::gpgSetPrimaryUID)
    );
    registerMethod("gpgSetSubkeyExpire",
      make_method(this, &webpgPluginAPI::gpgSetSubkeyExpire)
    );
    registerMethod("gpgSetPubkeyExpire",
      make_method(this, &webpgPluginAPI::gpgSetPubkeyExpire)
    );
    registerMethod("gpgExportPublicKey",
      make_method(this, &webpgPluginAPI::gpgExportPublicKey)
    );
    registerMethod("gpgPublishPublicKey",
      make_method(this, &webpgPluginAPI::gpgPublishPublicKey)
    );
    registerMethod("gpgRevokeKey",
      make_method(this, &webpgPluginAPI::gpgRevokeKey));
    registerMethod("gpgRevokeUID",
      make_method(this, &webpgPluginAPI::gpgRevokeUID)
    );
    registerMethod("gpgRevokeSignature",
      make_method(this, &webpgPluginAPI::gpgRevokeSignature)
    );
    registerMethod("gpgChangePassphrase",
      make_method(this, &webpgPluginAPI::gpgChangePassphrase)
    );
    registerMethod("gpgShowPhoto",
      make_method(this, &webpgPluginAPI::gpgShowPhoto));
    registerMethod("gpgAddPhoto",
      make_method(this, &webpgPluginAPI::gpgAddPhoto)
    );
    registerMethod("gpgGetPhotoInfo",
      make_method(this, &webpgPluginAPI::gpgGetPhotoInfo)
    );

    registerMethod("setTempGPGOption",
      make_method(this, &webpgPluginAPI::setTempGPGOption)
    );
    registerMethod("restoreGPGConfig",
      make_method(this, &webpgPluginAPI::restoreGPGConfig)
    );
    registerMethod("getTemporaryPath",
      make_method(this, &webpgPluginAPI::getTemporaryPath)
    );

    registerMethod("sendMessage",
      make_method(this, &webpgPluginAPI::sendMessage)
    );

    registerMethod("setStringMode",
      make_method(this, &webpgPluginAPI::setStringMode)
    );

//  gpgAuth related methods
#ifdef WITH_GPGAUTH
//    registerMethod("getDomainKey",
//      make_method(this, &webpg::getNamedKey));
//    registerMethod("verifyDomainKey",
//      make_method(this, &webpg::verifyDomainKey));
#endif

    registerEvent("onkeygenprogress");
    registerEvent("onkeygencomplete");
    registerEvent("onstatusprogress");
  }

  // Read-only properties
  registerProperty("version",
  make_property(this,
    &webpgPluginAPI::get_version)
  );

  registerProperty("webpg_status",
    make_property(this,
        &webpgPluginAPI::get_webpg_status)
  );

  registerProperty("openpgp_detected",
    make_property(this,
      &webpgPluginAPI::openpgp_detected)
  );

  registerProperty("gpgconf_detected",
    make_property(this,
      &webpgPluginAPI::gpgconf_detected)
  );

  m_webpgAPI = boost::make_shared<webpg>();

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
/// @fn webpgPluginPtr getPlugin()
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

///////////////////////////////////////////////////////////////////////////////
/// @fn void init()
///
/// @brief  Initializes the webpgPlugin and sets the status variables.
///////////////////////////////////////////////////////////////////////////////
void webpgPluginAPI::init()
{
  FB::VariantMap response;
  FB::VariantMap plugin_info;
  Json::Value sm = m_webpgAPI->get_webpg_status();
  response = FB::jsonValueToVariant(sm).convert_cast<FB::VariantMap>();

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
  size_t opera_ext = location.find("widget://");
  size_t safari_ext = location.find("safari-extension://");
  response["extension"] =
    (chrome_ext != std::string::npos) ? "chrome" :
    (firefox_ext != std::string::npos) ? "firefox" :
    (opera_ext != std::string::npos) ? "opera" :
    (safari_ext != std::string::npos) ? "safari" : "unknown";
#endif

  webpgPluginAPI::webpg_status_map = response;
};

void webpgPluginAPI::getKeyListThreadCaller(
    const std::string& name,
    bool secret_only,
    bool fast,
    webpgPluginAPI* api
) {
    api->m_webpgAPI->getKeyListWorker(
      name,
      secret_only,
      fast,
      api,
      &webpgPluginAPI::keylist_progress_cb
    );
};

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant getPublicKeyList()
///
/// @brief  Calls m_webpgAPI->getKeyList() without specifying a search
///         string, and the secret_only paramter as false, which returns only
///         Public Keys from the keyring.
///////////////////////////////////////////////////////////////////////////////
/*
    This method executes webpg->getKeyList with an empty string and
        secret_only=false which returns all Public Keys in the keyring.
*/
FB::variant webpgPluginAPI::getPublicKeyList(
    const boost::optional<bool> fast=false,
    const boost::optional<bool> async=false
) {
  Json::Value json_value;
  bool fastListMode = (fast==true);

  if (async == true) {
    boost::thread keylist_thread(
      boost::bind(
        &webpgPluginAPI::getKeyListThreadCaller,
        "",
        false,
        fastListMode,
        this
      )
    );
    json_value["status"] = "queued";
  } else {
    // Retrieve the public keylist
    json_value = m_webpgAPI->getPublicKeyList(fastListMode);
  }

  // Retrieve a reference to the DOM Window
  FB::DOM::WindowPtr window = m_host->getDOMWindow();

  if (!STRINGMODE) {
    // Check if the DOM Window has an in-built JSON Parser
    if (window && window->getJSObject()->HasProperty("JSON")) {
      // Create a writer that will convert the object to a string
      Json::FastWriter writer;

      // Create a reference to the browswer JSON object
      FB::JSObjectPtr obj = window->getProperty<FB::JSObjectPtr>("JSON");

      return obj->Invoke("parse", FB::variant_list_of(writer.write(json_value)));
    } else {
      FB::variant keylist = FB::jsonValueToVariant(json_value);
      // No browser JSON parser detected, falling back to return of FB::variant
      return keylist;
    }
  } else {
    Json::FastWriter writer;
    return writer.write(json_value);
  }
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant getPrivateKeyList()
///
/// @brief  Calls m_webpgAPI->getKeyList() without specifying a search
///         string, and the secret_only paramter as true, which returns only
///         Private Keys from the keyring.
///////////////////////////////////////////////////////////////////////////////
/*
    This method executes webpg->getKeyList with an empty string and
        secret_only=true which returns all Public Keys in the keyring.
*/
FB::variant webpgPluginAPI::getPrivateKeyList(
    const boost::optional<bool>fast=false,
    const boost::optional<bool> async=false
) {
  Json::Value json_value;
  bool fastListMode = (fast==true);

  if (async == true) {
    boost::thread keylist_thread(
      boost::bind(
        &webpgPluginAPI::getKeyListThreadCaller,
        "",
        true,
        fastListMode,
        this
      )
    );
    json_value["status"] = "queued";
  } else {
    // Retrieve the public keylist
    json_value = m_webpgAPI->getPrivateKeyList(fastListMode);
  }

  // Retrieve a reference to the DOM Window
  FB::DOM::WindowPtr window = m_host->getDOMWindow();

  if (!STRINGMODE) {
    // Check if the DOM Window has an in-built JSON Parser
    if (window && window->getJSObject()->HasProperty("JSON")) {
      // Create a writer that will convert the object to a string
      Json::FastWriter writer;

      // Create a reference to the browswer JSON object
      FB::JSObjectPtr obj = window->getProperty<FB::JSObjectPtr>("JSON");

      return obj->Invoke("parse", FB::variant_list_of(
        writer.write(json_value))
      );
    } else {
      FB::variant keylist = FB::jsonValueToVariant(json_value);
      // No browser JSON parser detected, falling back to return of FB::variant
      return keylist;
    }
  } else {
    Json::FastWriter writer;
    return writer.write(json_value);
  }
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant webpgPluginAPI::getNamedKey(const std::string& name)
///
/// @brief  Calls m_webpgAPI->getNamedKey() with a search string and the
///         secret_only paramter as false, which returns only Public Keys from
///         the keyring.
///////////////////////////////////////////////////////////////////////////////
/*
    This method just calls m_webpgAPI->getKeyList with a name/email
        as the parameter
*/
FB::variant webpgPluginAPI::getNamedKey(
    const std::string& name,
    const boost::optional<bool> fast=false,
    const boost::optional<bool> async=false
) {
  Json::Value json_value;
  bool fastListMode = (fast==true);

  if (async == true) {
    boost::thread keylist_thread(
      boost::bind(
        &webpgPluginAPI::getKeyListThreadCaller,
        name,
        false,
        fastListMode,
        this
      )
    );
    json_value["status"] = "queued";
  } else {
    // Retrieve the public keylist
    json_value = m_webpgAPI->getNamedKey(name, false);
  }

  // Retrieve a reference to the DOM Window
  FB::DOM::WindowPtr window = m_host->getDOMWindow();

  // Check if the DOM Window has an in-built JSON Parser
  if (window && window->getJSObject()->HasProperty("JSON")) {
    // Create a writer that will convert the object to a string
    Json::FastWriter writer;

    // Create a reference to the browswer JSON object
    FB::JSObjectPtr obj = window->getProperty<FB::JSObjectPtr>("JSON");

    return obj->Invoke("parse", FB::variant_list_of(writer.write(json_value)));
  } else {
    FB::variant keylist = FB::jsonValueToVariant(json_value);
    // No browser JSON parser detected, falling back to return of FB::variant
    return keylist;
  }
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant getExternalKey(const std::string& name)
///
/// @brief  Calls m_webpgAPI->getKeyList() after setting the context to
///         external mode with a search string and the secret_only paramter as
///         false, which returns only Public Keys
///////////////////////////////////////////////////////////////////////////////
/*
    This method just calls m_webpgAPI->getKeyList with a name/email
        as the parameter
*/
FB::variant webpgPluginAPI::getExternalKey(const std::string& name)
{
  // Retrieve the public keylist
  Json::Value json_value = m_webpgAPI->getExternalKey(name);

  // Retrieve a reference to the DOM Window
  FB::DOM::WindowPtr window = m_host->getDOMWindow();

  // Check if the DOM Window has an in-built JSON Parser
  if (window && window->getJSObject()->HasProperty("JSON")) {
    // Create a writer that will convert the object to a string
    Json::FastWriter writer;

    // Create a reference to the browswer JSON object
    FB::JSObjectPtr obj = window->getProperty<FB::JSObjectPtr>("JSON");

    return obj->Invoke("parse", FB::variant_list_of(writer.write(json_value)));
  } else {
    FB::variant keylist = FB::jsonValueToVariant(json_value);
    // No browser JSON parser detected, falling back to return of FB::variant
    return keylist;
  }
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgSetPreference(
///     const std::string& preference,
///     const std::string& pref_value)
///
/// @brief  Attempts to set the specified gpgconf preference with the value
///         of pref_value.
///
/// @param  preference  The preference to set.
/// @param  pref_value  The value to assign to the specified preference.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgSetPreference(
    const std::string& preference,
    const std::string& pref_value="blank"
) {
  Json::Value json_value = m_webpgAPI->gpgSetPreference(
    preference,
    pref_value
  );
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgGetPreference(const std::string& preference)
///
/// @brief  Attempts to set the specified gpgconf preference with the value
///         of pref_value.
///
/// @param  preference  The preference to set.
/// @param  pref_value  The value to assign to the specified preference.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgGetPreference(const std::string& preference)
{
  Json::Value json_value = m_webpgAPI->gpgGetPreference(preference);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgSetGroup(
///     const std::string& group,
///     const std::string& group_value)
///
/// @brief  Attempts to define or clear the specified group preference with
///         the value of group_value.
///
/// @param  group  The group to set.
/// @param  group_value  The value to assign to the specified group.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgSetGroup(
    const std::string& group,
    const std::string& group_value=""
) {
  Json::Value json_value = m_webpgAPI->gpgSetGroup(group, group_value);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgSetHomeDir(const std::string& gnupg_path)
///
/// @brief  Sets the GNUPGHOME static variable to the path specified in
///         gnupg_path. This should be called prior to initializing the
///         gpgme context.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgSetHomeDir(const std::string& gnupg_path)
{
  Json::Value json_value = m_webpgAPI->gpgSetHomeDir(gnupg_path);
  return FB::jsonValueToVariant(json_value);
}

FB::variant webpgPluginAPI::gpgGetHomeDir()
{
  Json::Value json_value = m_webpgAPI->gpgGetHomeDir();
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgSetBinary(const std::string& gnupg_exec)
///
/// @brief  Sets the GNUPGBIN static variable to the path specified in
///         gnupg_exec. This should be called prior to initializing the
///         gpgme context.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgSetBinary(const std::string& gnupg_exec)
{
  Json::Value json_value = m_webpgAPI->gpgSetBinary(gnupg_exec);
  return FB::jsonValueToVariant(json_value);
}

FB::variant webpgPluginAPI::gpgGetBinary()
{
  Json::Value json_value = m_webpgAPI->gpgGetBinary();
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgSetGPGConf(const std::string& gpgconf_exec)
///
/// @brief  Sets the GPGCONF static variable to the path specified in
///         gpgconf_exec.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgSetGPGConf(const std::string& gpgconf_exec)
{
  Json::Value json_value = m_webpgAPI->gpgSetGPGConf(gpgconf_exec);
  return FB::jsonValueToVariant(json_value);
}

FB::variant webpgPluginAPI::gpgGetGPGConf()
{
  Json::Value json_value = m_webpgAPI->gpgGetGPGConf();
  return FB::jsonValueToVariant(json_value);
}

FB::variant webpgPluginAPI::gpgEncrypt(
    const std::string& data,
    const FB::VariantList& enc_to_keyids,
    const boost::optional<bool>& sign,
    const boost::optional<FB::VariantList>& opt_signers
) {
  Json::Value json_value = m_webpgAPI->gpgEncrypt(
    data,
    variantToJsonValue(enc_to_keyids),
    sign,
    variantToJsonValue(opt_signers)
  );
  return FB::jsonValueToVariant(json_value);
}

FB::variant webpgPluginAPI::gpgSymmetricEncrypt(
    const std::string& data,
    const boost::optional<bool>& sign,
    const boost::optional<FB::VariantList>& opt_signers
) {
  Json::Value json_value = m_webpgAPI->gpgSymmetricEncrypt(
    data,
    sign,
    FB::variantToJsonValue(opt_signers)
  );
  return FB::jsonValueToVariant(json_value);
}

FB::variant webpgPluginAPI::gpgDecryptVerify(
    const std::string& data,
    const std::string& plaintext,
    int use_agent
) {
  Json::Value json_value = m_webpgAPI->gpgDecryptVerify(
    data,
    plaintext,
    use_agent
  );
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant webpgPluginAPI::gpgDecrypt(const std::string& data)
///
/// @brief  Calls m_webpgAPI->gpgDecryptVerify() with the use_agent flag
///         specifying to not disable the gpg-agent.
///
/// @param  data    The data to decyrpt.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgDecrypt(const std::string& data)
{
  Json::Value json_value = m_webpgAPI->gpgDecrypt(data);
  return FB::jsonValueToVariant(json_value);
}

FB::variant webpgPluginAPI::gpgVerify(
    const std::string& data,
    const boost::optional<std::string>& plaintext
) {
  Json::Value json_value = m_webpgAPI->gpgVerify(data, plaintext);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgSignText(
///     const std::string& plain_text,
///     FB::VariantList& signers,
///     int sign_mode)
///
/// @brief  Signs the text specified in plain_text with the key ids specified
///         in signers, with the signature mode specified in sign_mode.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgSignText(
    const std::string& plain_text,
    const FB::VariantList& signers,
    const boost::optional<int>& opt_sign_mode
) {
  Json::Value json_value = m_webpgAPI->gpgSignText(
    plain_text,
    FB::variantToJsonValue(signers),
    opt_sign_mode
  );
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant webpgPluginAPI::gpgSignUID(
///     const std::string& keyid,
///     long sign_uid,
///     const std::string& with_keyid,
///     long local_only,
///     long trust_sign,
///     long trust_level)
///
/// @brief  Signs the UID index of the specified keyid using the signing key
///         with_keyid.
///
/// @param  keyid    The ID of the key with the desired UID to sign.
/// @param  sign_uid    The 0 based index of the UID.
/// @param  with_keyid  The ID of the key to create the signature with.
/// @param  local_only  Specifies if the signature is local only (non exportable).
/// @param  trust_sign  Specifies if this is a trust signature.
/// @param  trust_level The level of trust to assign.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgSignUID(
    const std::string& keyid,
    long uid,
    const std::string& with_keyid,
    long local_only,
    long trust_sign,
    long trust_level,
    const boost::optional<std::string>& notation_name=NULL,
    const boost::optional<std::string>& notation_value=NULL
) {
  Json::Value json_value = m_webpgAPI->gpgSignUID(
    keyid,
    uid,
    with_keyid,
    local_only,
    trust_sign,
    trust_level,
    notation_name,
    notation_value
  );
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant webpgPluginAPI::gpgDeleteUIDSign(const std::string& keyid, long uid, long signature)
///
/// @brief  Deletes the Signature signature on the uid of keyid.
///
/// @param  keyid    The ID of the key containing the UID to delete the signature from.
/// @param  uid    The index of the UID containing the signature to delete.
/// @param  signature   The signature index of the signature to delete.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgDeleteUIDSign(
    const std::string& keyid,
    long sign_uid,
    long signature
) {
  Json::Value json_value = m_webpgAPI->gpgDeleteUIDSign(
    keyid,
    sign_uid,
    signature
  );
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant webpgPluginAPI::gpgEnableKey(const std::string& keyid)
///
/// @brief  Sets the key specified with keyid as enabled in gpupg.
///
/// @param  keyid    The ID of the key to enable.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgEnableKey(const std::string& keyid)
{
  Json::Value json_value = m_webpgAPI->gpgEnableKey(keyid);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant webpgPluginAPI::gpgDisableKey(const std::string& keyid)
///
/// @brief  Sets the key specified with keyid as disabled in gpupg.
///
/// @param  keyid   The ID of the key to disable.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgDisableKey(const std::string& keyid)
{
  Json::Value json_value = m_webpgAPI->gpgDisableKey(keyid);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn std::string webpgPluginAPI::gpgGenKey(const std::string& key_type,
///                                           const std::string& key_length,
///                                           const std::string& subkey_type,
///                                           const std::string& subkey_length,
///                                           const std::string& name_real,
///                                           const std::string& name_comment,
///                                           const std::string& name_email,
///                                           const std::string& expire_date,
///                                           const std::string& passphrase)
///
/// @brief  Queues a threaded gpg genkey operation.
///
/// @param  key_type    The key type to genereate.
/// @param  key_length    The size of the key to generate.
/// @param  subkey_type   The subkey type to generate.
/// @param  subkey_length   The size of the subkey to genereate.
/// @param  name_real   The name to assign the UID.
/// @param  name_comment    The comment to assign to the UID.
/// @param  name_email  The email address to assign to the UID.
/// @param  expire_date The expiration date to assign to the generated key.
/// @param  passphrase  The passphrase to assign the to the key.
///////////////////////////////////////////////////////////////////////////////
std::string webpgPluginAPI::gpgGenKey(
    const std::string& key_type,
    const std::string& key_length,
    const std::string& subkey_type,
    const std::string& subkey_length,
    const std::string& name_real,
    const std::string& name_comment,
    const std::string& name_email,
    const std::string& expire_date,
    const std::string& passphrase
) {

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
      this, params
    )
  );

  return "queued";
}

///////////////////////////////////////////////////////////////////////////////
/// @fn std::string gpgGenSubKey(const std::string& keyid,
///                              const std::string& subkey_type,
///                              const std::string& subkey_length,
///                              const std::string& subkey_expire,
///                              bool sign_flag,
///                              bool enc_flag,
///                              bool auth_flag)
///
/// @brief  Queues a threaded gpg gensubkey operation.
///
/// @param  keyid    The key to generate the subkey on.
/// @param  subkey_type   The subkey type to generate.
/// @param  subkey_length   The size of the subkey to genereate.
/// @param  subkey_expire The expiration date to assign to the generated subkey.
/// @param  sign_flag  Set the sign capabilities flag.
/// @param  enc_flag    Set the encrypt capabilities flag.
/// @param  auth_flag  Set the auth capabilities flag.
///////////////////////////////////////////////////////////////////////////////
std::string webpgPluginAPI::gpgGenSubKey(
    const std::string& keyid,
    const std::string& subkey_type,
    const std::string& subkey_length,
    const std::string& subkey_expire,
    bool sign_flag,
    bool enc_flag,
    bool auth_flag
) {

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
      this, params
    )
  );

  return "queued";
}

///////////////////////////////////////////////////////////////////////////////
/// @fn void keygen_progress_cb(void *self,
///                      const char *what,
///                      int type,
///                      int current,
///                      int total)
///
/// @brief  Called by the long-running, asymmetric gpg genkey method to
///         display the key generation status.
///
/// @param  self    A reference to webpgPluginAPI, since the method is called
///                 outside of the class.
/// @param  what    The current action status from gpg genkey.
/// @param  type    The type of of action.
/// @param  current ?
/// @param  total   ?
///////////////////////////////////////////////////////////////////////////////
void webpgPluginAPI::keygen_progress_cb(
    void *self,
    const char *what,
    int type,
    int current,
    int total
) {
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

void webpgPluginAPI::keylist_progress_cb(void *self, const std::string& msg_value) {
  if (msg_value.length() > 0) {
    webpgPluginAPI* API = (webpgPluginAPI*) self;
    API->FireEvent("onstatusprogress", FB::variant_list_of(msg_value));
  }
}

///////////////////////////////////////////////////////////////////////////////
/// @fn void threaded_gpgGenKey(genKeyParams params)
///
/// @brief  Calls gpgGenKeyWorker() with the specified parameters.
///
/// @param  params   The parameters used to generete the key.
///////////////////////////////////////////////////////////////////////////////
void webpgPluginAPI::threaded_gpgGenKey(genKeyParams params)
{
  m_webpgAPI->gpgGenKeyWorker(params, this, &webpgPluginAPI::keygen_progress_cb);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn void threaded_gpgGenSubKey(genKeyParams params)
///
/// @brief  Calls m_webpgAPI->gpgGenSubKeyWorker() with the specified parameters.
///
/// @param  params   The parameters used to generete the subkey.
///////////////////////////////////////////////////////////////////////////////
void webpgPluginAPI::threaded_gpgGenSubKey(genSubKeyParams params)
{
  m_webpgAPI->gpgGenSubKeyWorker(params, this, &webpgPluginAPI::keygen_progress_cb);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgImportKey(const std::string& ascii_key)
///
/// @brief  Imports the ASCII encoded key ascii_key
///
/// @param  ascii_key   An armored, ascii encoded PGP Key block.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgImportKey(const std::string& ascii_key)
{
  Json::Value json_value = m_webpgAPI->gpgImportKey(ascii_key);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgImportExternalKey(const std::string& ascii_key)
///
/// @brief  Imports the ASCII encoded key ascii_key
///
/// @param  ascii_key   An armored, ascii encoded PGP Key block.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgImportExternalKey(const std::string& keyid)
{
  Json::Value json_value = m_webpgAPI->gpgImportExternalKey(keyid);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgDeletePublicKey(const std::string& keyid)
///
/// @brief  Deletes key specified in keyid from the Public keyring.
///
/// @param  keyid   The ID of the key to delete from the Public keyring.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgDeletePublicKey(const std::string& keyid)
{
  Json::Value json_value = m_webpgAPI->gpgDeletePublicKey(keyid);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgDeletePrivateKey(const std::string& keyid)
///
/// @brief  Deletes key specified in keyid from the Private keyring.
///
/// @param  keyid   The ID of the key to delete from the Private keyring.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgDeletePrivateKey(const std::string& keyid)
{
  Json::Value json_value = m_webpgAPI->gpgDeletePrivateKey(keyid);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgDeletePrivateSubKey(const std::string& keyid,
///                                        int key_idx)
///
/// @brief  Deletes subkey located at index key_idx form the key specified in keyid.
///
/// @param  keyid   The ID of the key to delete the subkey from.
/// @param  key_idx The index of the subkey to delete.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgDeletePrivateSubKey(
    const std::string& keyid,
    int key_idx
) {
  Json::Value json_value = m_webpgAPI->gpgDeletePrivateSubKey(keyid, key_idx);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgSetKeyTrust(const std::string& keyid,
///                                long trust_level)
///
/// @brief  Sets the gnupg trust level assignment for the given keyid.
///
/// @param  keyid   The ID of the key to assign the trust level on.
/// @param  trust_level The level of trust to assign.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgSetKeyTrust(
    const std::string& keyid,
    long trust_level
) {
  Json::Value json_value = m_webpgAPI->gpgSetKeyTrust(keyid, trust_level);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgAddUID(const std::string& keyid,
///                           const std::string& name,
///                           const std::string& email,
///                           const std::string& comment)
///
/// @brief  Adds a new UID to the key specified by keyid
///
/// @param  keyid   The ID of the key to add the UID to.
/// @param  name    The name to assign to the new UID.
/// @param  email   The email address to assign to the new UID.
/// @param  comment The comment to assign to the new UID.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgAddUID(
    const std::string& keyid,
    const std::string& name,
    const std::string& email,
    const std::string& comment
) {
  Json::Value json_value = m_webpgAPI->gpgAddUID(
    keyid,
    name,
    email,
    comment
  );
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgDeleteUID(const std::string& keyid, long uid_idx)
///
/// @brief  Deletes the UID specified by uid_idx from the key specified with keyid.
///
/// @param  keyid   The ID of the key to delete to the specified UID from.
/// @param  uid_idx The index of the UID to delete from the key.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgDeleteUID(
    const std::string& keyid,
    long uid_idx
) {
  Json::Value json_value = m_webpgAPI->gpgDeleteUID(keyid, uid_idx);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgSetPrimaryUID(const std::string& keyid, long uid_idx)
///
/// @brief  Sets a given UID as the primary for the key specified with keyid.
///
/// @param  keyid   The ID of the key with the UID to make primary.
/// @param  uid_idx The index of the UID to make primary on the key.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgSetPrimaryUID(
    const std::string& keyid,
    long uid_idx
) {
  Json::Value json_value = m_webpgAPI->gpgSetPrimaryUID(keyid, uid_idx);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgSetPubkeyExpire(const std::string& keyid, long expire)
///
/// @brief  Sets the expiration of the public key of the given keyid.
///
/// @param  keyid   The ID of the key to set the expiration on.
/// @param  expire  The expiration to assign to the key.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgSetPubkeyExpire(
    const std::string& keyid,
    long expire
) {
  Json::Value json_value = m_webpgAPI->gpgSetPubkeyExpire(keyid, expire);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgSetSubkeyExpire(const std::string& keyid,
///                                    long key_idx,
///                                    long expire)
///
/// @brief  Sets the expiration of the subkey specified with <key_idx> on the
///         key specified with <keyid>.
///
/// @param  keyid   The ID of the key to set the expiration on.
/// @param  key_idx The index of the subkey to set the expiration on.
/// @param  expire  The expiration to assign to the key.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgSetSubkeyExpire(
    const std::string& keyid,
    long key_idx,
    long expire
) {
  Json::Value json_value = m_webpgAPI->gpgSetSubkeyExpire(
    keyid,
    key_idx,
    expire
  );
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgExportPublicKey(const std::string& keyid)
///
/// @brief  Exports the public key specified with <keyid> as an ASCII armored
///         PGP Block.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgExportPublicKey(const std::string& keyid)
{
  Json::Value json_value = m_webpgAPI->gpgExportPublicKey(keyid);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgPublishPublicKey(const std::string& keyid)
///
/// @brief  Exports the key specified by <keyid> to the configured keyserver
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgPublishPublicKey(const std::string& keyid)
{
  Json::Value json_value = m_webpgAPI->gpgPublishPublicKey(keyid);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgRevokeKey(const std::string& keyid,
///                              int key_idx,
///                              int reason,
///                              const std::string &desc)
///
/// @brief  Revokes the given subkey with the reason and description specified.
///
/// @param  keyid   The ID of the key to revoke.
/// @param  key_idx The index of the subkey to revoke.
/// @param  reason  The gnupg reason for the revocation.
/// @param  desc    The text description for the revocation.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgRevokeKey(
    const std::string& keyid,
    int key_idx, int reason,
    const std::string &desc
) {
  Json::Value json_value = m_webpgAPI->gpgRevokeKey(
    keyid,
    key_idx,
    reason,
    desc
  );
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgRevokeUID(const std::string& keyid,
///                              int uid_idx,
///                              int reason,
///                              const std::string &desc)
///
/// @brief  Revokes the given UID with the reason and description specified.
///
/// @param  keyid   The ID of the key with the UID to revoke.
/// @param  uid_idx The index of the UID to revoke.
/// @param  reason  The gnupg reason for the revocation.
/// @param  desc    The text description for the revocation.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgRevokeUID(
    const std::string& keyid,
    int uid_idx, int reason,
    const std::string &desc
) {
  Json::Value json_value = m_webpgAPI->gpgRevokeUID(
    keyid,
    uid_idx,
    reason,
    desc
  );
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgRevokeSignature(const std::string& keyid,
///                                    int uid_idx,
///                                    int sig_idx,
///                                    int reason,
///                                    const std::string &desc)
///
/// @brief  Revokes the given signature on the specified UID of key <keyid>
///         with the reason and description specified.
///
/// @param  keyid   The ID of the key with the signature to revoke.
/// @param  uid_idx The index of the UID with the signature to revoke.
/// @param  sig_idx The index of the signature to revoke.
/// @param  reason  The gnupg reason for the revocation.
/// @param  desc    The text description for the revocation.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgRevokeSignature(
    const std::string& keyid,
    int uid_idx,
    int sig_idx,
    int reason,
    const std::string &desc
) {
  Json::Value json_value = m_webpgAPI->gpgRevokeSignature(
    keyid,
    uid_idx,
    sig_idx,
    reason,
    desc
  );
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant gpgChangePassphrase(const std::string& keyid)
///
/// @brief  Invokes the gpg-agent to change the passphrase for the given key.
///
/// @param  keyid   The ID of the key to change the passphrase.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::gpgChangePassphrase(const std::string& keyid)
{
  Json::Value json_value = m_webpgAPI->gpgChangePassphrase(keyid);
  return FB::jsonValueToVariant(json_value);
}

void webpgPluginAPI::gpgShowPhoto(const std::string& keyid)
{
    m_webpgAPI->gpgShowPhoto(keyid);
}

FB::variant webpgPluginAPI::gpgAddPhoto(
    const std::string& keyid,
    const std::string& photo_name,
    const std::string& photo_data
) {
  Json::Value json_value = m_webpgAPI->gpgAddPhoto(
    keyid,
    photo_name,
    photo_data
  );
  return FB::jsonValueToVariant(json_value);
}

FB::variant webpgPluginAPI::gpgGetPhotoInfo(const std::string& keyid)
{
  Json::Value json_value = m_webpgAPI->gpgGetPhotoInfo(keyid);
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant setTempGPGOption(const std::string& option,
///                                  const std::string& value)
///
/// @brief  Creates a backup of the gpg.conf file and writes the options to
///         gpg.conf; This should be called prior to initializing the context.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::setTempGPGOption(
    const std::string& option,
    const std::string& value=NULL
) {
  Json::Value json_value = m_webpgAPI->setTempGPGOption(
    option,
    value
  );
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant restoreGPGConfig()
///
/// @brief  Restores the gpg.conf file from memory or the backup file.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::restoreGPGConfig()
{
  Json::Value json_value = m_webpgAPI->restoreGPGConfig();
  return FB::jsonValueToVariant(json_value);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant getTemporaryPath()
///
/// @brief  Attempts to determine the system or user temporary path.
///////////////////////////////////////////////////////////////////////////////
FB::variant webpgPluginAPI::getTemporaryPath()
{
  Json::Value json_value = m_webpgAPI->getTemporaryPath();
  return FB::jsonValueToVariant(json_value);
}

FB::VariantMap webpgPluginAPI::get_webpg_status()
{
  webpgPluginAPI::init();
  return webpgPluginAPI::webpg_status_map;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn std::string get_version()
///
/// @brief  Retruns the defined plugin version
///////////////////////////////////////////////////////////////////////////////
// Read-only property version
std::string webpgPluginAPI::get_version()
{
  return FBSTRING_PLUGIN_VERSION;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn bool openpgp_detected()
///
/// @brief  Determines if OpenPGP is available as a valid engine.
///////////////////////////////////////////////////////////////////////////////
bool webpgPluginAPI::openpgp_detected()
{
  return m_webpgAPI->openpgp_detected();
}

///////////////////////////////////////////////////////////////////////////////
/// @fn bool gpgconf_detected()
///
/// @brief  Determines gpgconf is available to the engine.
///////////////////////////////////////////////////////////////////////////////
bool webpgPluginAPI::gpgconf_detected()
{
  return m_webpgAPI->gpgconf_detected();
}

webpgPtr webpgPluginAPI::createWebPG()
{
  return boost::make_shared<webpg>();
}

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant setStringMode(const bool& value)
///
/// @brief  Sets the return of JSON data as a JSON string (not parsed)
///////////////////////////////////////////////////////////////////////////////
void webpgPluginAPI::setStringMode(const bool& value)
{
  STRINGMODE = value;
}

MultipartMixed webpgPluginAPI::createMessage(
    const FB::VariantMap& recipients_m,
    const FB::VariantList& signers,
    int messageType, // Signed, Encrypted
    const std::string& subject,
    const std::string& msgBody
) {
  // define the MultipartMixed message envelope
  MultipartMixed message;
  Json::Value crypto_result;
  Json::Value pgpData;
  std::string boundary = "webpg-";

  // Parse the supplied recipient list
  std::string recip_from = VariantValue(recipients_m, "from")
    .convert_cast<std::string>();
  FB::VariantList to_list = VariantValue(recipients_m, "to")
    .convert_cast<FB::VariantList>();
  FB::VariantList cc_list = VariantValue(recipients_m, "cc")
    .convert_cast<FB::VariantList>();
  FB::VariantList bcc_list = VariantValue(recipients_m, "bcc")
    .convert_cast<FB::VariantList>();
  FB::VariantList recip_keys = VariantValue(recipients_m, "keys")
    .convert_cast<FB::VariantList>();

  // Add the timestamp to the envelope
  time_t timestamp = time(NULL);
  char timestamptext[32];
  if (strftime(
      timestamptext,
      sizeof(timestamptext),
      "%a, %d %b %Y %H:%M:%S +0000",
      gmtime(&timestamp)
     )) {
    Field dateField;
    dateField.name("Date");
    dateField.value(timestamptext);
    message.header().push_back(dateField);
  }

  Field mimeVersion_h;
  mimeVersion_h.name("MIME-Version");
  mimeVersion_h.value(WEBPG_MIME_VERSION_STRING);
  message.header().push_back(mimeVersion_h);

  Field webpgVersion_h;
  webpgVersion_h.name("X-WebPG-Version");
  webpgVersion_h.value(FBSTRING_PLUGIN_VERSION);
  message.header().push_back(webpgVersion_h);

  // Add the FROM, TO, CC and BCC fields to the envelope
  message.header().from(recip_from.c_str());
  FB::variant lrecip;
  int nrecip;
  for (nrecip = 0; nrecip < to_list.size(); nrecip++) {
    lrecip = to_list[nrecip];
    message.header().to().push_back((char *) lrecip
      .convert_cast<std::string>().c_str());
  }
  for (nrecip = 0; nrecip < cc_list.size(); nrecip++) {
    lrecip = cc_list[nrecip];
    message.header().cc().push_back((char *) lrecip
      .convert_cast<std::string>().c_str());
  }
  for (nrecip = 0; nrecip < bcc_list.size(); nrecip++) {
    lrecip = bcc_list[nrecip];
    message.header().bcc().push_back((char *) lrecip
      .convert_cast<std::string>().c_str());
  }
  message.header().subject(subject.c_str());

  Attachment* att;

  if (messageType == WEBPG_PGPMIME_SIGNED) {
    // Create the pgp-signature ContentType and protocol
    message.header().contentType("multipart/signed");
    message.header().contentType().param("micalg", "pgp-sha1");
    message.header().contentType().param("protocol",
      "application/pgp-signature");

    message.body()
      .preamble("This is an OpenPGP/MIME signed message (RFC 4880 and 3156)");

    // create the plain object.
    MimeEntity* plain;
    plain = new MimeEntity();

    // Create the relevent headers for the plain MimeEntity
    plain->header().contentType().set("text/html; charset=ISO-8859-1");
    plain->header().contentTransferEncoding("quoted-printable");

    std::string msgBodyWH;

    plain->body().assign(msgBody.c_str());
    plain->body().push_back(NEWLINE);
    plain->body().push_back(NEWLINE);
    QP::Encoder qp;
    plain->body().code(qp);
    std::cout << plain->header().contentType().str() << std::endl;
    msgBodyWH = "Content-Type: ";
    msgBodyWH += plain->header().contentType().str();
    msgBodyWH += "\r\nContent-Transfer-Encoding: ";
    msgBodyWH += plain->header().contentTransferEncoding().str();
    msgBodyWH += "\r\n\r\n";
    msgBodyWH += plain->body();

    crypto_result = variantToJsonValue(webpgPluginAPI::gpgSignText(msgBodyWH,
                                                signers,
                                                1));
    pgpData = crypto_result["data"];
//    std::cout << crypto_result << std::endl;
    // Push the plain MimeEntity into the MimeMultipart message
    message.body().parts().push_back(plain);

    att = new Attachment("signature.asc",
                         ContentType("application","pgp-signature")
    );
    att->header().contentDescription("OpenPGP digital signature");
    att->header().contentTransferEncoding("quoted-printable");
    att->body().assign(pgpData.asString());

  } else {

    crypto_result = variantToJsonValue(webpgPluginAPI::gpgEncrypt(msgBody,
                                               recip_keys,
                                               true,
                                               signers));

    pgpData = crypto_result["data"];
    std::cout << pgpData << std::endl;
    // Assign the pgp-encrypted ContentType and protocol
    message.header().contentType("multipart/encrypted");
    message
      .header()
        .contentType()
          .param("protocol", "application/pgp-encrytped");

    // Set the body preamble
    message
      .body()
        .preamble("This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)");
    att = new Attachment("encrypted.asc",
                    ContentType("application","octet-stream")
    );
    att->header().contentDescription("OpenPGP encrypted message");
    att->body().assign(pgpData.asString());
    att->body().push_back(NEWLINE);
  }

  char buf[16];
  snprintf(buf, 16, "%lu", time(NULL));
  boundary += buf;
  message.header().contentType().param("boundary", boundary);

//  if (formatInline == true) {
//    // Add the MIME Version message part
//    MimeEntity* mimeVersion;
//    mimeVersion = new MimeEntity();
//    mimeVersion->header().contentType(message.header().contentType().param("protocol"));
//    mimeVersion->header().contentDescription("PGP/MIME version identification");
//    mimeVersion->body().assign("Version: ");
//    mimeVersion->body().push_back(WEBPG_MIME_VERSION_STRING[0]);
//    mimeVersion->body().push_back(NEWLINE);
//    message.body().parts().push_back(mimeVersion);

//    att->header().contentTransferEncoding("inline");
//  }

  // Push the attachment into the MimeMultipart message
  message.body().parts().push_back(att);

  return message;
}

static size_t readcb(void *ptr, size_t size, size_t nmemb, void *stream) {
  readarg_t *rarg = (readarg_t *)stream;
  int len = rarg->body_size - rarg->body_pos;
  if (len > size * nmemb)
    len = size * nmemb;
  memcpy(ptr, rarg->data + rarg->body_pos, len);
  rarg->body_pos += len;
  printf("readcb: %d bytes\n", len);
  return len;
}

FB::variant webpgPluginAPI::sendMessage(const FB::VariantMap& msgInfo) {
  int nrecip;
  std::string username = VariantValue(msgInfo, "username")
    .convert_cast<std::string>();
  std::string bearer = VariantValue(msgInfo, "bearer")
    .convert_cast<std::string>();
  FB::VariantMap recipients_m = VariantValue(msgInfo, "recipients")
    .convert_cast<FB::VariantMap>();
  std::string recip_from = VariantValue(recipients_m, "from")
    .convert_cast<std::string>();
  FB::VariantList to_list = VariantValue(recipients_m, "to")
    .convert_cast<FB::VariantList>();
  FB::VariantList cc_list = VariantValue(recipients_m, "cc")
    .convert_cast<FB::VariantList>();
  FB::VariantList bcc_list = VariantValue(recipients_m, "bcc")
    .convert_cast<FB::VariantList>();
  FB::VariantList signers = VariantValue(msgInfo, "signers")
    .convert_cast<FB::VariantList>();
  std::string subject = VariantValue(msgInfo, "subject")
    .convert_cast<std::string>();
  std::string msgBody = VariantValue(msgInfo, "message")
    .convert_cast<std::string>();

  // convert the newlines in msgBody
  boost::replace_all(msgBody, "\n", "\r\n");

  int msgType = VariantValue(msgInfo, "messagetype").convert_cast<int>();
//  bool formatInline = VariantValue(msgInfo, "formatinline").convert_cast<bool>();

  MultipartMixed me =
    createMessage(recipients_m,
    signers,
    msgType,
    subject,
    msgBody
  );
  std::stringstream buffer;
  buffer << me << endl;
  std::string buffern = buffer.str();
  std::cout << buffern << std::endl;

  readarg_t rarg;
  rarg.data = (char *) buffern.c_str();
  rarg.body_size = buffern.size();
  rarg.body_pos = 0;

  CURL *curl;
  CURLcode res;
  struct curl_slist *recipients = NULL;

  curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.gmail.com:587");

    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_USERNAME, (char *) username.c_str());
    curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, (char *) bearer.c_str());

    /* value for envelope reverse-path */
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, (char *) recip_from.c_str());
    /* Add two recipients, in this particular case they correspond to the
     * To: and Cc: addressees in the header, but they could be any kind of
     * recipient. */

    FB::variant lrecip;
    for (nrecip = 0; nrecip < to_list.size(); nrecip++) {
      lrecip = to_list[nrecip];
      recipients = curl_slist_append(recipients, (char *) lrecip
        .convert_cast<std::string>().c_str());
    }
//      recipients = curl_slist_append(recipients, CC);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    res = curl_easy_setopt(curl, CURLOPT_READFUNCTION, readcb);
    if(res != CURLE_OK)
      return curl_easy_strerror(res);
    res = curl_easy_setopt(curl, CURLOPT_READDATA, &rarg);
    if(res != CURLE_OK)
      return curl_easy_strerror(res);

    /* Since the traffic will be encrypted, it is very useful to turn on debug
     * information within libcurl to see what is happening during the transfer.
     */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* send the message (including headers) */
    res = curl_easy_perform(curl);

    /* Check for errors */
    if(res != CURLE_OK)
      return curl_easy_strerror(res);

    /* free the list of recipients and clean up */
    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
  }

  return buffer.str();
}
