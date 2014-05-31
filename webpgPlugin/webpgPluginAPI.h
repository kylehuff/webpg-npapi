/**********************************************************\
Original Author: Kyle L. Huff (kylehuff)

Created:    Jan 14, 2011
License:    GNU General Public License, version 2
            http://www.gnu.org/licenses/gpl-2.0.html

Copyright 2011 Kyle L. Huff, CURETHEITCH development team
\**********************************************************/
/*! \mainpage webpg-npapi Documentation
 *
 * \section intro_sec Introduction
 *
 * webpg-npapi is an NPAPI plugin project that provides GnuPG related \
 * Public/Private Key operations for use in major browsers.
 * \n
 * \n
 *
 * \section install_sec Compiling
 *
 * \subsection step1 Step 1: Obtain the source
 *
 * git clone http://github.com/kylehuff/webpg-npapi.git\n
 * \n
 *
 * \subsection step2 Step 2: Retreieve the submodules
 *
 * cd webpg-npapi\n
 * git submodule init\n
 * git submodule update --recursive\n
 * \n
 *
 * \subsection step3 Step 3: Create the build environment
 *
 * \subsection linux Linux: cmake
 *
 * ./firebreath/prepmake.sh webpgPlugin build\n
 *
 * \subsection osx OSX: cmake/XCode
 *
 * ./firebreath/prepmac.sh webpgPlugin build\n
 *
 * \subsection win Windows: cmake/VS 2005, 2008, 2010
 *
 * firebreath/prep{VS version}.cmd webpgPlugin build\n
 * \n
 *
 * \subsection step4 Step 4: Build the source
 *
 * cmake --build build --config webpgPlugin --target MinSizeRel
 *
 *
 *
 *
 *
 *
 *
 */

#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include "JSObject.h"
#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include <boost/optional.hpp>
#include <boost/algorithm/string.hpp>

#if _MSC_VER
#define snprintf _snprintf
#endif

#include "libwebpg/webpg.h"

#include "webpgPlugin.h"

#include "fbjson.h"
#include <boost/weak_ptr.hpp>
#include "FBPointers.h"

FB_FORWARD_PTR(webpgPluginAPI);
FB_FORWARD_PTR(webpg);

#ifndef H_webpgPluginAPI
#define H_webpgPluginAPI

//typedef struct {
//  FB::variant host_url;
//  FB::variant username;
//  FB::variant bearer;
//  FB::VariantMap recipients;
//  FB::VariantList signers;
//  FB::variant subject;
//  FB::variant message;
//} msgParams;

//typedef struct {
//  char *data;
//  int body_size;
//  int body_pos;
//} readarg_t;

static bool STRINGMODE = false;
const int kMaxCharPerLine = 76;
const char* const kEOL = "\r\n";

const char kHexTable[] = "0123456789ABCDEF";

inline FB::variant VariantValue(const FB::VariantMap& vmap, std::string key) {
  FB::VariantMap::const_iterator it;
  FB::variant value;

  it = vmap.find(key);

  if (it != vmap.end()) {
    if (it->second.is_of_type<FB::VariantMap>())
      value = "VariantMap";
    else if (it->second.is_of_type<FB::VariantList>())
      value = "VaraintList";
    else
      value = it->second;
  }

  return value;
}

inline FB::VariantMap VariantMapValue(const FB::VariantMap& vmap, std::string key) {
  FB::VariantMap::const_iterator it;
  FB::VariantMap value;

  it = vmap.find(key);

  if (it != vmap.end())
    value = it->second.convert_cast<FB::VariantMap>();

  return value;
}

inline FB::VariantList VariantListValue(const FB::VariantMap& vmap, std::string key) {
  FB::VariantMap::const_iterator it;
  FB::VariantList value;

  it = vmap.find(key);

  if (it != vmap.end())
    value = it->second.convert_cast<FB::VariantList>();

  return value;
}

///////////////////////////////////////////////////////////////////////////////
/// @class  webpgPluginAPI
///
/// @brief  Main webpg Class
///////////////////////////////////////////////////////////////////////////////
class webpgPluginAPI : public FB::JSAPIAuto
{
  public:
    webpgPluginAPI(const webpgPluginPtr& plugin,
        const FB::BrowserHostPtr& host);
    virtual ~webpgPluginAPI();

    webpgPluginPtr getPlugin();

    webpgPtr createWebPG();

    FB::VariantMap webpg_status_map;

    ///////////////////////////////////////////////////////////////////////////
    /// @fn void init()
    ///
    /// @brief  Initializes the webpgPlugin and sets the status variables.
    ///////////////////////////////////////////////////////////////////////////
    void init();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::getPublicKeyList()
    ///
    /// @brief  Calls webpgPluginAPI::getKeyList() without specifying a search
    ///         string, and the secret_only paramter as false, which returns only
    ///         Public Keys from the keyring.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant getPublicKeyList(
      const boost::optional<bool> fast,
      const boost::optional<bool> async
    );

    void threaded_getPublicKeyList();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant getPrivateKeyList()
    ///
    /// @brief  Calls webpgPluginAPI::getKeyList() without specifying a search
    ///         string, and the secret_only paramter as true, which returns only
    ///         Private Keys from the keyring.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant getPrivateKeyList(
        const boost::optional<bool> fast,
        const boost::optional<bool> async
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant getNamedKey(const std::string& name)
    ///
    /// @brief  Calls webpgPluginAPI::getKeyList() with a search string and the
    ///         secret_only paramter as false, which returns only Public Keys from
    ///         the keyring.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant getNamedKey(
        const std::string& name,
        const boost::optional<bool> fast,
        const boost::optional<bool> async
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant getExternalKey(const std::string& name)
    ///
    /// @brief  Calls webpgPluginAPI::getKeyList() after setting the context to
    ///         external mode with a search string and the secret_only paramter as
    ///         "0", which returns only Public Keys
    ///////////////////////////////////////////////////////////////////////////
    FB::variant getExternalKey(const std::string& name);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant gpgSetPreference(const std::string& preference,
    ///                                  const std::string& pref_value)
    ///
    /// @brief  Attempts to set the specified gpgconf preference with the value
    ///         of pref_value.
    ///
    /// @param  preference  The preference to set.
    /// @param  pref_value  The value to assign to the specified preference.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSetPreference(
        const std::string& preference,
        const std::string& pref_value
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant gpgGetPreference(const std::string& preference)
    ///
    /// @brief  Attempts to gett the specified gpgconf preference with the value
    ///         of pref_value.
    ///
    /// @param  preference  The preference to set.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgGetPreference(const std::string& preference);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgSetGroup(
    ///                                         const std::string& group,
    ///                                         const std::string& group_value)
    ///
    /// @brief  Attempts to define or clear the specified group preference
    ///         with the value of <group_value>.
    ///
    /// @param  group  The group to set.
    /// @param  group_value  The value to assign to the specified group.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSetGroup(
        const std::string& group,
        const std::string& group_value
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgSetHomeDir(const std::string& gnupg_path)
    ///
    /// @brief  Sets the GNUPGHOME static variable to the path specified in
    ///         gnupg_path. This should be called prior to initializing the
    ///         gpgme context.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSetHomeDir(const std::string& gnupg_path);
    FB::variant gpgGetHomeDir();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgSetBinary(const std::string& gnupg_exec)
    ///
    /// @brief  Sets the GNUPGBIN static variable to the path specified in
    ///         gnupg_exec. This should be called prior to initializing the
    ///         gpgme context.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSetBinary(const std::string& gnupg_exec);
    FB::variant gpgGetBinary();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgSetGPGConf(const std::string& gpgconf_exec)
    ///
    /// @brief  Sets the GPGCONF static variable to the path specified in
    ///         gpgconf_exec.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSetGPGConf(const std::string& gpgconf_exec);
    FB::variant gpgGetGPGConf();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgEncrypt(const std::string& data, const FB::VariantList& enc_to_keyids, bool sign)
    ///
    /// @brief  Encrypts the data passed in data with the key ids passed in
    ///         enc_to_keyids and optionally signs the data.
    ///
    /// @param  data    The data to encrypt.
    /// @param  enc_to_keyids   A VariantList of key ids to encrypt to (recpients).
    /// @param  sign    The data should be also be signed.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgEncrypt(
        const std::string& data,
        const FB::VariantList& enc_to_keyids,
        const boost::optional<bool>& sign,
        const boost::optional<FB::VariantList>& opt_signers
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgSymmetricEncrypt(const std::string& data, bool sign)
    ///
    /// @brief  Calls webpgPluginAPI::gpgEncrypt() without any recipients specified
    ///         which initiates a Symmetric encryption method on the gpgme context.
    ///
    /// @param  data    The data to symmetrically encrypt.
    /// @param  sign    The data should also be signed. NOTE: Signed symmetric
    ///                 encryption does not work in gpgme v1.3.2; For details,
    ///                 see https://bugs.g10code.com/gnupg/issue1440
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSymmetricEncrypt(
        const std::string& data,
        const boost::optional<bool>& sign,
        const boost::optional<FB::VariantList>& opt_signers
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgDecryptVerify(const std::string& data, const std::string& plaintext, int use_agent)
    ///
    /// @brief  Attempts to decrypt and verify the string data. If use_agent
    ///         is 0, it will attempt to disable the key-agent to prevent the
    ///         passphrase dialog from displaying. This is useful in cases where
    ///         you want to verify or decrypt without unlocking the private keyring
    ///         (i.e. in an automated parsing environment).
    ///
    /// @param  data    The data to decrypt and/or verify.
    /// @param  plaintext   The plaintext of a detached signature.
    /// @param  use_agent   Attempt to disable the gpg-agent.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgDecryptVerify(
        const std::string& data,
        const std::string& plaintext,
        int use_agent
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgDecrypt(const std::string& data)
    ///
    /// @brief  Calls webpgPluginAPI::gpgDecryptVerify() with the use_agent flag
    ///         specifying to not disable the gpg-agent.
    ///
    /// @param  data    The data to decyrpt.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgDecrypt(const std::string& data);

    FB::variant gpgVerify(
        const std::string& data,
        const boost::optional<std::string>& plaintext
    );
    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgSignText(FB::VariantList& signers, const std::string& plain_text, int sign_mode)
    ///
    /// @brief  Signs the text specified in plain_text with the key ids specified
    ///         in signers, with the signature mode specified in sign_mode.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSignText(
      const std::string& plain_text,
      const FB::VariantList& signers,
      const boost::optional<int>& opt_sign_mode
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgSignUID(const std::string& keyid, long sign_uid, const std::string& with_keyid, long local_only, long trust_sign, long trust_level)
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
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSignUID(
      const std::string& keyid,
      long uid,
      const std::string& with_keyid,
      long local_only,
      long trust_sign,
      long trust_level,
      const boost::optional<std::string>& notation_name,
      const boost::optional<std::string>& notation_value
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgDeleteUIDSign(const std::string& keyid, long uid, long signature)
    ///
    /// @brief  Deletes the Signature signature on the uid of keyid.
    ///
    /// @param  keyid    The ID of the key containing the UID to delete the signature from.
    /// @param  uid    The index of the UID containing the signature to delete.
    /// @param  signature   The signature index of the signature to delete.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgDeleteUIDSign(
        const std::string& keyid,
        long sign_uid,
        long signature
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgEnableKey(const std::string& keyid)
    ///
    /// @brief  Sets the key specified with keyid as enabled in gpupg.
    ///
    /// @param  keyid    The ID of the key to enable.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgEnableKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgDisableKey(const std::string& keyid)
    ///
    /// @brief  Sets the key specified with keyid as disabled in gpupg.
    ///
    /// @param  keyid   The ID of the key to disable.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgDisableKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn std::string webpgPluginAPI::gpgGenKey(const std::string& key_type, const std::string& key_length,
    ///        const std::string& subkey_type, const std::string& subkey_length, const std::string& name_real,
    ///        const std::string& name_comment, const std::string& name_email, const std::string& expire_date,
    ///        const std::string& passphrase)
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
    ///////////////////////////////////////////////////////////////////////////
    std::string gpgGenKey(
        const std::string& key_type,
        const std::string& key_length,
        const std::string& subkey_type,
        const std::string& subkey_length,
        const std::string& name_real,
        const std::string& name_comment,
        const std::string& name_email,
        const std::string& expire_date,
        const std::string& passphrase
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn std::string webpgPluginAPI::gpgGenSubKey(const std::string& keyid,
    ///         const std::string& subkey_type, const std::string& subkey_length,
    ///         const std::string& subkey_expire, bool sign_flag, bool enc_flag, bool auth_flag)
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
    ///////////////////////////////////////////////////////////////////////////
    std::string gpgGenSubKey(
        const std::string& keyid,
        const std::string& subkey_type, const std::string& subkey_length,
        const std::string& subkey_expire, bool sign_flag, bool enc_flag,
        bool auth_flag
    );

    /*
        static class method which accepts the calling object as a parameter
            so it can thread a member function
    */
    static void genKeyThreadCaller(webpgPluginAPI* api, genKeyParams params)
    {
        api->threaded_gpgGenKey(params);
    };

    static void genSubKeyThreadCaller(webpgPluginAPI* api,
        genSubKeyParams params)
    {
        api->threaded_gpgGenSubKey(params);
    };

    static void getKeyListThreadCaller(
        const std::string& name,
        bool secret_only,
        bool fast,
        webpgPluginAPI* api
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn void webpgPluginAPI::keygen_progress_cb(void *self, const char *what, int type, int current, int total)
    ///
    /// @brief  Called by the long-running, asymmetric gpg genkey method to display the status.
    ///
    /// @param  self    A reference to webpgPluginAPI, since the method is called
    ///                 outside of the class.
    /// @param  what    The current action status from gpg genkey.
    /// @param  type    The type of of action.
    /// @param  current ?
    /// @param  total   ?
    ///////////////////////////////////////////////////////////////////////////
    static void keygen_progress_cb(
        void *self, const char *what,
        int type, int current, int total
    );

    static void keylist_progress_cb(void *self, const char* msg_value);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn void webpgPluginAPI::threaded_gpgGenKey(genKeyParams params)
    ///
    /// @brief  Calls webpgPluginAPI::gpgGenKeyWorker() with the specified parameters.
    ///
    /// @param  params   The parameters used to generete the key.
    ///////////////////////////////////////////////////////////////////////////
    void threaded_gpgGenKey(genKeyParams params);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn void webpgPluginAPI::threaded_gpgGenSubKey(genKeyParams params)
    ///
    /// @brief  Calls gpgGenSubKeyWorker() with the specified parameters.
    ///
    /// @param  params   The parameters used to generete the subkey.
    ///////////////////////////////////////////////////////////////////////////
    void threaded_gpgGenSubKey(genSubKeyParams params);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgImportKey(const std::string& ascii_key)
    ///
    /// @brief  Imports the ASCII encoded key ascii_key
    ///
    /// @param  ascii_key   An armored, ascii encoded PGP Key block.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgImportKey(const std::string& ascii_key);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgImportExternalKey(const std::string& ascii_key)
    ///
    /// @brief  Imports the ASCII encoded key ascii_key
    ///
    /// @param  ascii_key   An armored, ascii encoded PGP Key block.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgImportExternalKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgDeletePublicKey(const std::string& keyid)
    ///
    /// @brief  Deletes key specified in keyid from the Public keyring.
    ///
    /// @param  keyid   The ID of the key to delete from the Public keyring.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgDeletePublicKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgDeletePrivateKey(const std::string& keyid)
    ///
    /// @brief  Deletes key specified in keyid from the Private keyring.
    ///
    /// @param  keyid   The ID of the key to delete from the Private keyring.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgDeletePrivateKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgDeletePrivateSubKey(const std::string& keyid, int key_idx)
    ///
    /// @brief  Deletes subkey located at index key_idx form the key specified in keyid.
    ///
    /// @param  keyid   The ID of the key to delete the subkey from.
    /// @param  key_idx The index of the subkey to delete.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgDeletePrivateSubKey(const std::string& keyid, int key_idx);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgSetKeyTrust(const std::string& keyid, long trust_level)
    ///
    /// @brief  Sets the gnupg trust level assignment for the given keyid.
    ///
    /// @param  keyid   The ID of the key to assign the trust level on.
    /// @param  trust_level The level of trust to assign.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSetKeyTrust(const std::string& keyid, long trust_level);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgAddUID(const std::string& keyid, const std::string& name,
    ///     const std::string& email, const std::string& comment)
    ///
    /// @brief  Adds a new UID to the key specified by keyid
    ///
    /// @param  keyid   The ID of the key to add the UID to.
    /// @param  name    The name to assign to the new UID.
    /// @param  email   The email address to assign to the new UID.
    /// @param  comment The comment to assign to the new UID.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgAddUID(
        const std::string& keyid,
        const std::string& name,
        const std::string& email,
        const std::string& comment
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgDeleteUID(const std::string& keyid, long uid_idx)
    ///
    /// @brief  Deletes the UID specified by uid_idx from the key specified with keyid.
    ///
    /// @param  keyid   The ID of the key to delete to the specified UID from.
    /// @param  uid_idx The index of the UID to delete from the key.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgDeleteUID(const std::string& keyid, long uid_idx);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgSetPrimaryUID(const std::string& keyid, long uid_idx)
    ///
    /// @brief  Sets a given UID as the primary for the key specified with keyid.
    ///
    /// @param  keyid   The ID of the key with the UID to make primary.
    /// @param  uid_idx The index of the UID to make primary on the key.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSetPrimaryUID(const std::string& keyid, long uid_idx);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgSetKeyExpire(const std::string& keyid, long key_idx, long expire)
    ///
    /// @brief  Sets the expiration of the given key_idx on the key keyid with the expiration of expire.
    ///
    /// @param  keyid   The ID of the key to set the expiration on.
    /// @param  key_idx The index of the subkey to set the expiration on.
    /// @param  expire  The expiration to assign.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSetKeyExpire(
        const std::string& keyid,
        long key_idx,
        long expire
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgSetPubkeyExpire(const std::string& keyid, long expire)
    ///
    /// @brief  Sets the expiration of the public key of the given keyid.
    ///
    /// @param  keyid   The ID of the key to set the expiration on.
    /// @param  expire  The expiration to assign to the key.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSetPubkeyExpire(const std::string& keyid, long expire);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgSetSubkeyExpire(const std::string& keyid, long key_idx, long expire)
    ///
    /// @brief  Sets the expiration of the subkey specified with key_idx on the key specified with keyid.
    ///
    /// @param  keyid   The ID of the key to set the expiration on.
    /// @param  key_idx The index of the subkey to set the expiration on.
    /// @param  expire  The expiration to assign to the key.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgSetSubkeyExpire(
        const std::string& keyid,
        long key_idx,
        long expire
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgExportPublicKey(const std::string& keyid)
    ///
    /// @brief  Exports the public key specified with keyid as an ASCII armored encoded PGP Block.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgExportPublicKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgPublishPublicKey(const std::string& keyid)
    ///
    /// @brief  Exports the key specified by keyid to the configured keyserver
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgPublishPublicKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgRevokeKey(const std::string& keyid, int key_idx, int reason,
    ///    const std::string &desc)
    ///
    /// @brief  Revokes the given key/subkey with the reason and description specified.
    ///
    /// @param  keyid   The ID of the key to revoke.
    /// @param  key_idx The index of the subkey to revoke.
    /// @param  reason  The gnupg reason for the revocation.
    /// @param  desc    The text description for the revocation.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgRevokeKey(
        const std::string& keyid,
        int key_idx,
        int reason,
        const std::string &desc
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgRevokeUID(const std::string& keyid, int uid_idx, int reason,
    ///    const std::string &desc)
    ///
    /// @brief  Revokes the given UID with the reason and description specified.
    ///
    /// @param  keyid   The ID of the key with the UID to revoke.
    /// @param  uid_idx The index of the UID to revoke.
    /// @param  reason  The gnupg reason for the revocation.
    /// @param  desc    The text description for the revocation.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgRevokeUID(
        const std::string& keyid,
        int uid_idx,
        int reason,
        const std::string &desc
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgRevokeSignature(const std::string& keyid, int uid_idx, int sig_idx,
    ///    int reason, const std::string &desc)
    ///
    /// @brief  Revokes the given signature on the specified UID of key keyid with the reason and description specified.
    ///
    /// @param  keyid   The ID of the key with the signature to revoke.
    /// @param  uid_idx The index of the UID with the signature to revoke.
    /// @param  sig_idx The index of the signature to revoke.
    /// @param  reason  The gnupg reason for the revocation.
    /// @param  desc    The text description for the revocation.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgRevokeSignature(
        const std::string& keyid,
        int uid_idx,
        int sig_idx,
        int reason,
        const std::string &desc
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::gpgChangePassphrase(const std::string& keyid)
    ///
    /// @brief  Invokes the gpg-agent to change the passphrase for the given key.
    ///
    /// @param  keyid   The ID of the key to change the passphrase.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant gpgChangePassphrase(const std::string& keyid);

    void gpgShowPhoto(const std::string& keyid);

    FB::variant gpgAddPhoto(
        const std::string& keyid,
        const std::string& photo_name,
        const std::string& photo_data
    );

    FB::variant gpgGetPhotoInfo(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::setTempGPGOption(const std::string& option, const std::string& value)
    ///
    /// @brief  Creates a backup of the gpg.conf file and writes the options to
    ///         gpg.conf; This should be called prior to initializing the context.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant setTempGPGOption(
        const std::string& option,
        const std::string& value
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::restoreGPGConfig()
    ///
    /// @brief  Restores the gpg.conf file from memory or the backup file.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant restoreGPGConfig();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::getTemporaryPath()
    ///
    /// @brief  Attempts to determine the system or user temporary path.
    ///////////////////////////////////////////////////////////////////////////
    FB::variant getTemporaryPath();

    FB::variant sendMessage(const FB::VariantMap& msgInfo);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn FB::variant webpgPluginAPI::get_webpg_status()
    ///
    /// @brief  Executes webpgPluginAPI::init() to set the status variables and
    ///         populates the "edit_status" property with the contents of the
    ///         edit_status constant.
    ///////////////////////////////////////////////////////////////////////////
    FB::VariantMap get_webpg_status();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn std::string webpgPluginAPI::get_version()
    ///
    /// @brief  Retruns the defined plugin version
    ///////////////////////////////////////////////////////////////////////////
    std::string get_version();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn bool webpgPluginAPI::openpgp_detected()
    ///
    /// @brief  Determines if OpenPGP is available as a valid engine.
    ///////////////////////////////////////////////////////////////////////////
    bool openpgp_detected();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn bool webpgPluginAPI::gpgconf_detected()
    ///
    /// @brief  Determines if gpgconf is available to the engine.
    ///////////////////////////////////////////////////////////////////////////
    bool gpgconf_detected();

    void setStringMode(const bool& value);
    FB_JSAPI_EVENT(prog, 1, (std::string));
  private:
    webpgPluginWeakPtr m_plugin;
    webpgPtr m_webpgAPI;
    FB::BrowserHostPtr m_host;
    int IsEOL(
        const std::string::const_iterator& iter,
        const std::string& input
    );
};

#endif // H_webpgPluginAPI
