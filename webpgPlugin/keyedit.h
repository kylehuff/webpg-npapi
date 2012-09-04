#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#endif

#include <stdlib.h>
#include <iostream>

// GNUGPGHOME need only be populated and all future context init's will use
//  the path as homedir for gpg
//#ifdef HAVE_W32_SYSTEM
//    wchar_t *GNUPGHOME;
//#else
std::string GNUPGHOME;
//#endif

// A global holder for the current edit_fnc status
std::string edit_status;

/* Global variables for the handling of UID signing or
    deleting signatures on UIDs */

// subkey_type
std::string gen_subkey_type;

// subkey_length
std::string gen_subkey_length;

// subkey_expire
std::string gen_subkey_expire;

// Flags for subkey generation
bool gen_sign_flag;
bool gen_enc_flag;
bool gen_auth_flag;

// index number of the UID which contains the signature to delete/revoke
std::string current_uid;

// index number for the signature to select
std::string current_sig;

// trust value to assign
std::string trust_assignment;

// uid name to create
std::string genuid_name;

// uid email to assign
std::string genuid_email;

// uid comment to assign
std::string genuid_comment;

// Used as iter count for current signature index
static int signature_iter;

// Used as iter count for current notation/description line
static int text_line;

// Used to store the index for the key/subkey
//  0: Public Key
//  1 &>: Subkeys
std::string key_index;

// Used to store the value for the new expiration
std::string expiration;

// Used to store the type of item to revoke
std::string revitem;

// Used to store the index of the of the revocation reason
// 0: No reason specified
// 1: Key has been compromised
// 2: Key is superseded
// 3: Key is no longer used
// -- UID revocation --
// 4: User ID is no longer used
std::string reason_index;

// Used to store the revocation description
std::string description;

// Used to keep track of the current edit iteration
static int step = 0;

static int flag_step = 0;

/* An inline method to convert an integer to a string */
inline
std::string i_to_str(const int &number)
{
   std::ostringstream oss;
   oss << number;
   return oss.str();
}

// Create a dummy passphrase callback for instances where we cannot prevent
//  the agent from prompting the user when we are merely attempting to verify
//  a PGP block (this is needed for GPG2 on Windows)
gpgme_error_t
passphrase_cb (void *opaque, const char *uid_hint, const char *passphrase_info,
	       int last_was_bad, int fd)
{
#ifdef HAVE_W32_SYSTEM
    DWORD written;
    WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
    int res;
    std::string pass = "\n";
    int passlen = pass.length();
    int off = 0;

    do {
        res = write (fd, &pass[off], passlen - off);
        if (res > 0)
        off += res;
    }
    while (res > 0 && off != passlen);

    return off == passlen ? 0 : gpgme_error_from_errno (errno);
#endif

  return 0;
}

gpgme_error_t
edit_fnc_sign (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
    /* this is stores the response to a questions that arise during
        the edit loop - it is what the user would normally type while
        using `gpg --edit-key`. To test the prompts and their output,
        you can execute GnuPG this way:
            gpg --command-fd 0 --status-fd 2 --edit-key <KEY ID>
     */
    char *response = NULL;
    int error = GPG_ERR_NO_ERROR;
    static std::string prior_response = "";
    static gpgme_status_code_t status_result;

    if (status != 49 && status != 51)
        status_result = status;

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    response = (char *) "fpr";
                    break;

                case 1:
                    response = (char *) current_uid.c_str();
                    break;

                case 2:
                    response = (char *) "tlsign";
                    break;

                default:
                    if (status_result && prior_response == "tlsign")
                        error = status_result; // there is a problem...
                    prior_response = "";
                    step = 0;
                    response = (char *) "quit";
                    break;
            }
            step++;
        }
        else if (!strcmp (args, "keyedit.save.okay"))
            response = (char *) "Y";
        else if (!strcmp (args, "trustsig_prompt.trust_value"))
            response = (char *) "1";
        else if (!strcmp (args, "trustsig_prompt.trust_depth"))
            response = (char *) "1";
        else if (!strcmp (args, "trustsig_prompt.trust_regexp"))
            response = (char *) "";
        else if (!strcmp (args, "sign_uid.okay"))
            response = (char *) "y";
        else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
            error = GPG_ERR_BAD_PASSPHRASE;
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
        prior_response = response;
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return error;
}


gpgme_error_t
edit_fnc_delsign (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this works for deleting signatures -
    you must populate the global variables before calling this method for this to work -
        current_uid = <the index of the UID which has the signature you wish to delete>
        current_sig = <the index of signature you wish to delete>  */
    char *response = NULL;

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    response = (char *) "fpr";
                    break;

                case 1:
                    signature_iter = 1;
                    response = (char *) current_uid.c_str();
                    break;

                case 2:
                    response = (char * ) "delsig";
                    break;

                default:
                    step = 0;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "keyedit.delsig.valid") || 
            !strcmp (args, "keyedit.delsig.invalid") ||
            !strcmp (args, "keyedit.delsig.unknown")) {
            if (signature_iter == atoi(current_sig.c_str())) {
                response = (char *) "y";
                current_sig = "0";
                current_uid = "0";
                signature_iter = 0;
            } else {
                response = (char *) "n";
            }
            signature_iter++;
        } else if (!strcmp (args, "keyedit.delsig.selfsig")) {
            response = (char *) "y";
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return 0;
}

gpgme_error_t
edit_fnc_disable (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this works for disabling keys */
    char *response = NULL;

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    response = (char *) "disable";
                    break;

                default:
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return 0;
}

gpgme_error_t
edit_fnc_enable (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this enableds a disabled key  */
    char *response = NULL;

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    response = (char *) "enable";
                    break;

                default:
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return 0;
}

gpgme_error_t
edit_fnc_assign_trust (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this assigns the trust to the key 
        the string trust_assignment must be populated before calling this method */
    char *response = NULL;

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    response = (char *) "trust";
                    break;

                default:
                    step = 0;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "edit_ownertrust.value")) {
            if (step < 15) {
                response = (char *) trust_assignment.c_str();
                step++;
            } else {
                response = (char *) "m";
            }
        } else if (!strcmp (args, "edit_ownertrust.set_ultimate.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return 0;
}

gpgme_error_t
edit_fnc_add_uid (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this creates a new UID for the given Key
        the strings genuid_name, genuid_email and genuid_comment must be populated before calling this method */

    char *response = NULL;

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    response = (char *) "adduid";
                    break;

                default:
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keygen.name")) {
            response = (char *) genuid_name.c_str();
        } else if (!strcmp (args, "keygen.email")) {
            if (strlen (genuid_email.c_str()) > 1) {
                response = (char *) genuid_email.c_str();
            } else {
                response = (char *) "";
            }
        } else if (!strcmp (args, "keygen.comment")) {
            if (strlen (genuid_comment.c_str()) > 1) {
                response = (char *) genuid_comment.c_str();
            } else {
                response = (char *) "";
            }
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
            step = 0;
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return 0;
}

gpgme_error_t
edit_fnc_delete_uid (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this deletes a UID for the given Key
        the string current_uid must be populated before calling this method */

    char *response = NULL;

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    response = (char *) current_uid.c_str();
                    break;

                case 1:
                	response = (char *) "deluid";
                	break;

                default:
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keyedit.remove.uid.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
            step = 0;
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return 0;
}

gpgme_error_t
edit_fnc_set_primary_uid (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this sets a given UID as the primary for the key
        the string current_uid must be populated before calling this method */

    char *response = NULL;

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    response = (char *) current_uid.c_str();
                    break;

                case 1:
                	response = (char *) "primary";
                	break;

                default:
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keyedit.remove.uid.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
            step = 0;
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return 0;
}

gpgme_error_t
edit_fnc_set_key_expire (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this sets the expiration for a given key
        the strings key_index and expiration must be populated before calling this method */

    char *response = NULL;
    std::string cmd;

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    cmd = "key ";
                    cmd += key_index;
                    response = (char *) cmd.c_str();
                    break;

                case 1:
                	response = (char *) "expire";
                	break;

                default:
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keygen.valid")) {
            response = (char *) expiration.c_str();
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
            step = 0;
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return 0;
}

gpgme_error_t
edit_fnc_revoke_item (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this revokes a given key, subkey or uid
        the global strings revitem, key_index, reason_index and desc_text must be populated
        before calling this method */

    char *response = NULL;
    std::string cmd;

    if (!strcmp (revitem.c_str(), "revkey")) {
            cmd = "key ";
            cmd += key_index;
    } else if (!strcmp (revitem.c_str(), "revuid")) {
            cmd = "uid ";
            cmd += current_uid;
    } else if (!strcmp (revitem.c_str(), "revsig")) {
            cmd = "uid ";
            cmd += current_uid;
    }

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    response = (char *) cmd.c_str();
                    break;

                case 1:
                    signature_iter = 0;
                    text_line = 1;
                	response = (char *) revitem.c_str();
                	break;

                default:
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keyedit.revoke.subkey.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "ask_revoke_sig.one")) {
            if (signature_iter == atoi(current_sig.c_str())) {
                response = (char *) "Y";
                current_sig = "0";
                current_uid = "0";
                signature_iter = 0;
            } else {
                response = (char *) "N";
            }
            signature_iter++;
        } else if (!strcmp (args, "keyedit.revoke.uid.okay")){
            response = (char *) "Y";
        } else if (!strcmp (args, "ask_revoke_sig.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "ask_revocation_reason.code")) {
            response = (char *) reason_index.c_str();
        } else if (!strcmp (args, "ask_revocation_reason.text")) {
            if (text_line > 1) {
                text_line = 1;
                response = (char *) "";
            } else {
                text_line++;
                response = (char *) description.c_str();
            }
        } else if (!strcmp (args, "ask_revocation_reason.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
            step = 0;
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return 0;
}

gpgme_error_t
edit_fnc_add_subkey (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this works for adding subkeys */
    char *response = NULL;

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    response = (char *) "addkey";
                    break;

                default:
                    response = (char *) "quit";
                    step = -1;
                    break;
            }
            step++;
        } else if (!strcmp (args, "keygen.algo")) {
            response = (char *) gen_subkey_type.c_str();
        } else if (!strcmp (args, "keygen.flags")) {
            static int flag_step = 0;

            switch (flag_step) {
                case 0:
                    // If the gen_sign_flag is set, we don't need to change
                    //  anything, as the sign_flag is set by default
                    if (gen_sign_flag) {
                        response = (char *) "nochange";
                    } else {
                        response = (char *) "S";
                    }
                    break;

                case 1:
                    // If the gen_enc_flag is set, we don't need to change
                    //  anything, as the enc_flag is set by default on keys
                    //  that support the enc flag (RSA)
                    if (gen_enc_flag) {
                        response = (char *) "nochange";
                    } else {
                        response = (char *) "E";
                    }
                    break;

                case 2:
                    if (gen_auth_flag) {
                        response = (char *) "A";
                    } else {
                        response = (char *) "nochange";
                    }
                    break;

                default:
                    response = (char *) "Q";
                    flag_step = -1;
                    break;

            }
            flag_step++;
        } else if (!strcmp (args, "keygen.size")) {
            response = (char *) gen_subkey_length.c_str();
        } else if (!strcmp (args, "keygen.valid")) {
            response = (char *) gen_subkey_expire.c_str();
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return 0;
}

gpgme_error_t
edit_fnc_delete_subkey (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this works for deleting subkeys */
    char *response = NULL;
    std::string cmd;
    cmd = "key ";
    cmd += key_index;
    response = (char *) cmd.c_str();

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    cmd = "key ";
                    cmd += key_index;
                    response = (char *) cmd.c_str();
                    break;

                case 1:
                    signature_iter = 1;
                    response = (char *) "delkey";
                    break;

                default:
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "keyedit.remove.subkey.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return 0;
}

gpgme_error_t
edit_fnc_change_passphrase (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this invokes a passphrase change. all I/O of passphrases should happen with the agent  */
    char *response = NULL;

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    response = (char *) "passwd";
                    break;

                default:
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        } else {
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        	edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": we should never reach here;";
        	return 1;
        }
    }

    if (response) {
        edit_status = edit_status + " " + args + ", case " + i_to_str(step) + ": response: " + response + ";";
#ifdef HAVE_W32_SYSTEM
        DWORD written;
        WriteFile ((HANDLE) fd, response, strlen (response), &written, 0);
        WriteFile ((HANDLE) fd, "\n", 1, &written, 0);
#else
        ssize_t write_result;
        write_result = write (fd, response, strlen (response));
        write_result = write (fd, "\n", 1);
#endif
    }
    return 0;
}
