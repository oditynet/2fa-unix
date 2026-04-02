#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <libudev.h>
#include <stdint.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define PASSWD_FILE "/etc/2fact/passwd"


struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

static int call_auth_api(const char *username, const char *pin, const char *token) {
    CURL *curl;
    CURLcode res;
    char *json_data = NULL;
    struct MemoryStruct chunk;
    long http_code = 0;
    int result = 0;

    chunk.memory = malloc(1);
    chunk.size = 0;

    asprintf(&json_data, "{\"username\":\"%s\",\"password\":\"%s\",\"token\":\"%s\"}",
             username, pin, token);

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    if (curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:13031/api/v1/auth");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        if (res == CURLE_OK && http_code == 200) {
            if (strstr(chunk.memory, "\"status\":\"ok\"")) {
                result = 1;
            }
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    free(json_data);
    free(chunk.memory);

    return result;
}

static int find_user_token(const char *username, char *token, size_t token_size) {
    FILE *f = fopen(PASSWD_FILE, "r");
    if (!f) {
        return 0;
    }

    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';

        char *colon = strchr(line, ':');
        if (!colon) continue;

        *colon = '\0';
        char *file_username = line;
        char *file_token = colon + 1;

        if (strcmp(file_username, username) == 0) {
            strncpy(token, file_token, token_size - 1);
            token[token_size - 1] = '\0';
            found = 1;
            break;
        }
    }

    fclose(f);
    return found;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SERVICE_ERR);
}

static void pamvprompt(pam_handle_t *pamh, int style, char **resp, char *fmt, va_list ap) {/*{{{*/
  struct pam_conv *conv;
  struct pam_message msg;
  const struct pam_message *msgp;
  struct pam_response *pamresp;
  int pam_err;
  char *text = "";

  vasprintf(&text, fmt, ap);

  pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  pam_set_item(pamh, PAM_AUTHTOK, NULL);

  msg.msg_style = style;;
  msg.msg = text;
  msgp = &msg;
  pamresp = NULL;
  pam_err = (*conv->conv)(1, &msgp, &pamresp, conv->appdata_ptr);

  if (pamresp != NULL) {
    if (resp != NULL)
      *resp = pamresp->resp;
    else
      free(pamresp->resp);
    free(pamresp);
  }

  free(text);
}

static int _converse(pam_handle_t *pamh, int nargs, const struct pam_message **message, struct pam_response **response) {
    struct pam_conv *conv;
    int retval;

    retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
    if (retval != PAM_SUCCESS) return retval;

    return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static char *converse(pam_handle_t *pamh, int echocode, const char *prompt) {
    const struct pam_message msg = {.msg_style = echocode, .msg = (char *)prompt};
    const struct pam_message *msgs = &msg;
    struct pam_response *resp = NULL;
    int retval = _converse(pamh, 1, &msgs, &resp);
    char *ret = NULL;

    if (retval == PAM_SUCCESS && resp && resp->resp && *resp->resp) {
        ret = strdup(resp->resp);
    }

    if (resp) {
        if (!ret) free(resp->resp);
        free(resp);
    }

    return ret;
}

static void pamprompt(pam_handle_t *pamh, int style, char **resp, char *fmt, ...) {/*{{{*/
  va_list ap;
  va_start(ap, fmt);
  pamvprompt(pamh, style, resp, fmt, ap);
  va_end(ap);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username = NULL;
    char *pin = NULL;
    char token[256] = {0};
    int auth_ok = 0;

    /* Получаем username через PAM */
    pam_get_item(pamh, PAM_USER, (const void **)&username);
    
    if (!username || strlen(username) == 0) {
        return PAM_AUTH_ERR;
    }

    /* Ищем токен пользователя в файле */
    if (!find_user_token(username, token, sizeof(token))) {
        //pam_info(pamh, "User %s not found in %s", username, PASSWD_FILE);
        return PAM_AUTH_ERR;
    }

    /* Запрашиваем PIN */
    pin = converse(pamh, PAM_PROMPT_ECHO_OFF, "PIN: ");
    if (!pin) {
        return PAM_AUTH_ERR;
    }

    /* Отправляем запрос на API */
    auth_ok = call_auth_api(username, pin, token);
    
    free(pin);

    return auth_ok ? PAM_SUCCESS : PAM_AUTH_ERR;
}







