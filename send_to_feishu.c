#include "send_to_feishu.h"
#include "purple2compat/http.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <debug.h>

#ifndef FEISHU_SECRET
#define FEISHU_SECRET "default_secret"
#endif

#ifndef FEISHU_WEBHOOK_URL
#define FEISHU_WEBHOOK_URL "default_url"
#endif

#ifndef FEISHU_TEMPLATE_ID
#define FEISHU_TEMPLATE_ID "default_template_id"
#endif

const char* secret = FEISHU_SECRET;
const char* webhook_url = FEISHU_WEBHOOK_URL;
const char* template_id = FEISHU_TEMPLATE_ID;

/**
 * Base64 encodes the given buffer.
 */
static char* base64_encode(const unsigned char* buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    char *b64text;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines
    BIO_write(b64, buffer, (int)length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);
    b64text = g_strndup(bufferPtr->data, bufferPtr->length);
    BIO_free_all(b64);
    return b64text;
}

/**
 * Generates HMAC-SHA256 signature for Feishu webhook
 */
static char* generate_signature(const char* secret, const char* timestamp) {
    char string_to_sign[128];
    snprintf(string_to_sign, sizeof(string_to_sign), "%s\n%s", timestamp, secret);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    HMAC(EVP_sha256(), secret, (int)strlen(secret),
         (unsigned char*)string_to_sign, strlen(string_to_sign),
         digest, &len);
    return base64_encode(digest, len);
}

/**
 * Get current local time as "HH:MM"
 */
static void get_current_time_str(char *buf, size_t bufsize) {
    time_t now = time(NULL);
    struct tm local_tm;
    localtime_r(&now, &local_tm);
    strftime(buf, bufsize, "%H:%M", &local_tm);
}

/**
 * Callback for the HTTP request, called when the response is received.
 */
static void feishu_post_cb(PurpleHttpConnection *conn, PurpleHttpResponse *resp, gpointer user_data) {
    if (purple_http_response_is_successful(resp)) {
        const char *data = purple_http_response_get_data(resp, NULL);
        purple_debug_info("feishu", "Send to Feishu succeeded: %s\n", data ? data : "(no response)");
    } else {
        const char *err = purple_http_response_get_error(resp);
        int code = purple_http_response_get_code(resp);
        purple_debug_error("feishu", "Send to Feishu failed: HTTP %d, error=%s\n", code, err ? err : "(unknown error)");
    }
}

/**
 * Send a message to Feishu card webhook.
 * Log progress to the Finch debug window.
 */
int send_to_feishu_card(const char *sender, const char *content) {
    char time_str[16];
    get_current_time_str(time_str, sizeof(time_str));

    time_t now = time(NULL);
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%ld", now);

    char *sign = generate_signature(secret, timestamp);
    if (!sign) {
        purple_debug_error("feishu", "Failed to generate signature\n");
        return 1;
    }

    // Compose card content
    char card[1024];
    snprintf(card, sizeof(card),
        "{\"type\":\"template\",\"data\":{\"template_id\":\"%s\",\"template_variable\":{\"TIME\":\"%s\",\"TITLE\":\"%s\",\"MSG\":\"%s\"}}}",
        template_id, time_str, sender ? sender : "", content ? content : ""
    );

    // Compose payload
    char payload[2048];
    snprintf(payload, sizeof(payload),
        "{\"timestamp\":%s,\"sign\":\"%s\",\"msg_type\":\"interactive\",\"card\":%s}",
        timestamp, sign, card
    );

    // Prepare HTTP request
    PurpleHttpRequest *req = purple_http_request_new(webhook_url);
    purple_http_request_set_method(req, "POST");
    purple_http_request_header_set(req, "Content-Type", "application/json");
    purple_http_request_set_contents(req, payload, -1);

    purple_debug_info("feishu", "Sending to Feishu: sender=%s, content=%s\n", sender, content);

    // Send the HTTP request asynchronously
    purple_http_request(NULL, req, feishu_post_cb, NULL);
    purple_http_request_unref(req);

    g_free(sign);
    return 0;
}
