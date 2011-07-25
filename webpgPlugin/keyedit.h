#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#endif

#include <stdlib.h>
#include <iostream>

/* Global variables for the handling of UID signing or
    deleting signatures on UIDs */
// index number of the UID which contains the signature to delete/revoke
std::string current_uid;
// index number for the signature to select
std::string current_sig;
// Used as iter count for current signature index
static int signature_iter = 1;
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
  /* this works for disabling keys -
    you must populate the global variables before calling this method for this to work -
        current_uid = <the index of the UID which has the signature you wish to delete>
        current_sig = <the index of signature you wish to delete>  */
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
