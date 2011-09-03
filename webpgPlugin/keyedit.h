#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#endif

#include <stdlib.h>
#include <iostream>

// A global holder for the current edit_fnc status
std::string edit_status;

/* Global variables for the handling of UID signing or
    deleting signatures on UIDs */

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
static int signature_iter = 1;

// Used to store the index for the key/subkey
//  0: Public Key
//  1 &>: Subkeys
std::string key_index;

// Used to store the value for the new expiration
std::string expiration;

// Used to keep track of the current edit iteration
static int step = 0;

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
        }
    }

    if (response) {
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
        }
    }

    if (response) {
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

                case 1:
                    response = (char *) "disable";
                    break;

                default:
                    step = 0;
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
        }
    }

    if (response) {
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

                case 1:
                    response = (char *) "enable";
                    break;

                default:
                    step = 0;
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
        	return 1;
        }
    }

    if (response) {
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
        	return 1;
        }
    }

    if (response) {
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
                    edit_status = edit_status + " " + args + " case 0;";
                    response = (char *) "adduid";
                    break;

                case 1:
                    edit_status = edit_status + " " + args + " case 1;";
                    step = -1;
                	response = (char *) "quit";
                	break;

                default:
                    edit_status = edit_status + " " + args + " case default, step-count: ?;";
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keygen.name")) {
            response = (char *) genuid_name.c_str();
            edit_status = edit_status + " " + args + ";";
        } else if (!strcmp (args, "keygen.email")) {
            if (strlen (genuid_email.c_str()) > 1) {
                response = (char *) genuid_email.c_str();
            } else {
                response = (char *) "";
            }
            edit_status = edit_status + " " + args + ";";
        } else if (!strcmp (args, "keygen.comment")) {
            if (strlen (genuid_comment.c_str()) > 1) {
                response = (char *) genuid_comment.c_str();
            } else {
                response = (char *) "";
            }
            edit_status = edit_status + " " + args + ";";
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
            edit_status = edit_status + " " + args + ";";
            step = 0;
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
            edit_status = edit_status + " " + args + ";";
        } else {
            edit_status = edit_status + " " + args + "never.here;";
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        }
    }

    if (response) {
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
                    edit_status = edit_status + " " + args + " case 0;";
                    response = (char *) current_uid.c_str();
                    break;

                case 1:
                    edit_status = edit_status + " " + args + " case 1;";
                	response = (char *) "deluid";
                	break;

                case 2:
                    edit_status = edit_status + " " + args + " case 2;";
                	response = (char *) "quit";
                	step = -1;
                	break;

                default:
                    edit_status = edit_status + " " + args + " case default, step-count: ?;";
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keyedit.remove.uid.okay")) {
            response = (char *) "Y";
            edit_status = edit_status + " " + args + ";";
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
            edit_status = edit_status + " " + args + ";";
            step = 0;
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
            edit_status = edit_status + " " + args + ";";
        } else {
            edit_status = edit_status + " " + args + "never.here;";
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        }
    }

    if (response) {
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
                    edit_status = edit_status + " " + args + " case 0;";
                    response = (char *) current_uid.c_str();
                    break;

                case 1:
                    edit_status = edit_status + " " + args + " case 1;";
                	response = (char *) "primary";
                	break;

                case 2:
                    edit_status = edit_status + " " + args + " case 2;";
                	response = (char *) "quit";
                	step = -1;
                	break;

                default:
                    edit_status = edit_status + " " + args + " case default, step-count: ?;";
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keyedit.remove.uid.okay")) {
            response = (char *) "Y";
            edit_status = edit_status + " " + args + ";";
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
            edit_status = edit_status + " " + args + ";";
            step = 0;
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
            edit_status = edit_status + " " + args + ";";
        } else {
            edit_status = edit_status + " " + args + "never.here;";
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        }
    }

    if (response) {
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
                    edit_status = edit_status + " " + args + " case 0;";
                    cmd = "key ";
                    cmd += key_index;
                    response = (char *) cmd.c_str();
                    break;

                case 1:
                    edit_status = edit_status + " " + args + " case 1;";
                	response = (char *) "expire";
                	break;

                case 2:
                    edit_status = edit_status + " " + args + " case 2;";
                	response = (char *) "quit";
                	step = -1;
                	break;

                default:
                    edit_status = edit_status + " " + args + " case default, step-count: ?;";
                    step = -1;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keygen.valid")) {
            response = (char *) expiration.c_str();
            edit_status = edit_status + " " + args + ";";
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
            edit_status = edit_status + " " + args + ";";
            step = 0;
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
            edit_status = edit_status + " " + args + ";";
        } else {
            edit_status = edit_status + " " + args + "never.here;";
        	fprintf (stdout, "We shouldn't reach this line actually; Line: %i\n", __LINE__);
        }
    }

    if (response) {
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
