/*
 * httptelnet.c
 *
 *  Created on: Oct 7, 2011
 *      Author: rogge
 */

#include "common/common_types.h"

#include "olsr_http.h"
#include "olsr_telnet.h"

#include "common/common_types.h"
#include "common/autobuf.h"

#include "olsr_cfg.h"
#include "olsr_http.h"
#include "olsr_logging.h"
#include "olsr_plugins.h"
#include "olsr_telnet.h"
#include "olsr.h"

/* constants */
#define _CFG_SECTION "httptelnet"

static const char *_HTTP_PATH = "/telnet";

/* prototypes */
static int _plugin_load(void);
static int _plugin_unload(void);
static int _plugin_enable(void);
static int _plugin_disable(void);

static enum olsr_http_result _cb_generate_site(
    struct autobuf *out, struct olsr_http_session *);

static void _config_changed(void);

/* html handler */
struct olsr_http_handler _http_site_handler = {
  .content_handler = _cb_generate_site,
};

/* plugin declaration */
OLSR_PLUGIN7 {
  .descr = "OLSRD http2telnet bridge plugin",
  .author = "Henning Rogge",

  .load = _plugin_load,
  .unload = _plugin_unload,
  .enable = _plugin_enable,
  .disable = _plugin_disable,

  .deactivate = true,
};

/* configuration */
static struct cfg_schema_section _httptelnet_section = {
  .t_type = _CFG_SECTION
};

static struct cfg_schema_entry _httptelnet_entries[] = {
  CFG_MAP_STRING(olsr_http_handler, site, "/telnet", "Path for http2telnet bridge"),
  CFG_MAP_ACL(olsr_http_handler, acl, "default_accept", "acl for http2telnet bridge"),
  CFG_MAP_STRINGLIST(olsr_http_handler, auth, "", "TODO"),
};

static struct cfg_delta_handler _httptelnet_delta_handler = {
  .s_type = _CFG_SECTION,
  .callback = _config_changed,
};

static const char *_last_site;

static int
_plugin_load(void) {
  _http_site_handler.site = strdup(_HTTP_PATH);
  if (_http_site_handler.site == NULL) {
    return -1;
  }

  _last_site = _http_site_handler.site;

  cfg_schema_add_section(olsr_cfg_get_schema(), &_httptelnet_section);
  cfg_schema_add_entries(&_httptelnet_section,
      _httptelnet_entries, ARRAYSIZE(_httptelnet_entries));

  cfg_delta_add_handler(olsr_cfg_get_delta(), &_httptelnet_delta_handler);

  olsr_acl_add(&_http_site_handler.acl);
  strarray_init(&_http_site_handler.auth);

  return 0;
}

static int
_plugin_unload(void) {
  strarray_free(&_http_site_handler.auth);
  olsr_acl_remove(&_http_site_handler.acl);
  free((char *)_http_site_handler.site);

  cfg_delta_remove_handler(olsr_cfg_get_delta(), &_httptelnet_delta_handler);
  cfg_schema_remove_section(olsr_cfg_get_schema(), &_httptelnet_section);
  return 0;
}

static int
_plugin_enable(void) {
  olsr_http_add(&_http_site_handler);
  return 0;
}

static int
_plugin_disable(void) {
  olsr_http_remove(&_http_site_handler);
  return 0;
}

static enum olsr_http_result
_cb_generate_site(struct autobuf *out, struct olsr_http_session *session) {
  const char *command, *param;

  command = olsr_http_lookup_param(session, "c");
  param = olsr_http_lookup_param(session, "p");

  if (command == NULL) {
    return HTTP_404_NOT_FOUND;
  }

  switch (olsr_telnet_execute(command, param, out, session->remote)) {
    case TELNET_RESULT_ACTIVE:
    case TELNET_RESULT_QUIT:
      session->content_type = HTTP_CONTENTTYPE_TEXT;
      return HTTP_200_OK;

    case TELNET_RESULT_UNKNOWN_COMMAND:
      return HTTP_404_NOT_FOUND;

    default:
      return HTTP_400_BAD_REQ;
  }
}

/**
 * Update configuration of remotecontrol plugin
 */
static void
_config_changed(void) {
  if (cfg_schema_tobin(&_http_site_handler, _httptelnet_delta_handler.post,
      _httptelnet_entries, ARRAYSIZE(_httptelnet_entries))) {
    OLSR_WARN(LOG_CONFIG, "Could not convert httptelnet config to bin");
    return;
  }

  if (_http_site_handler.site != _last_site) {
    _last_site = _http_site_handler.site;

    _plugin_disable();
    _plugin_enable();
  }
}
