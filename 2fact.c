#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
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

static int call_auth_api(const char *username, const char *password, const char *token) {
    CURL *curl;
    CURLcode res;
    char *json_data = NULL;
    struct MemoryStruct chunk;
    long http_code = 0;
    int result = 0;

    chunk.memory = malloc(1);
    chunk.size = 0;

    asprintf(&json_data, "{\"username\":\"%s\",\"password\":\"%s\",\"token\":\"%s\"}",
             username, password, token);

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

/* Ищет пользователя в файле паролей */
static int find_user_token(const char *username, char *token, size_t token_size) {
    FILE *f = fopen(PASSWD_FILE, "r");
    if (!f) {
        return 0;
    }

    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        /* Удаляем перевод строки */
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';

        /* Парсим строку: username:token */
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

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SERVICE_ERR;
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

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    char *username = NULL;
    char *password = NULL;
    char token[256] = {0};
    int auth_ok = 0;

    /* Получаем username из аргументов модуля */
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "username=", 9) == 0) {
            username = strdup(argv[i] + 9);
        }
    }

    if (!username) {
        //pam_info(pamh, "Username must be provided as module argument: username=xxx");
        if (username) free(username);
        return PAM_AUTH_ERR;
    }

    /* Ищем пользователя в файле /etc/2fact/passwd */
    if (!find_user_token(username, token, sizeof(token))) {
        //pam_info(pamh, "User %s not found in %s", username, PASSWD_FILE);
        free(username);
        return PAM_AUTH_ERR;
    }

    /* Запрашиваем пароль у пользователя */
    password = converse(pamh, PAM_PROMPT_ECHO_OFF, "PIN: ");
    if (!password) {
        free(username);
        return PAM_AUTH_ERR;
    }

    /* Отправляем на сервер username, password, token */
    auth_ok = call_auth_api(username, password, token);

    free(username);
    free(password);

    if (auth_ok) {
        return PAM_SUCCESS;
    }

    //pam_info(pamh, "Authentication failed");
    return PAM_AUTH_ERR;
}
