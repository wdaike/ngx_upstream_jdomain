/**
 * @file ngx_http_upstream_jdomain.c
 *
 * @brief Support upstream servers with re-resolved hostnames.
 *
 * this module (C) wudaike
 * this module (C) Baidu, Inc.
 **/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

/**
 * The supported states for DNS resolution for a particular server..
 */
#define NGX_JDOMAIN_STATUS_DONE 0
#define NGX_JDOMAIN_STATUS_WAIT 1

/**
 * The connection information for a specific peer.
 */
typedef struct {
  struct sockaddr       sockaddr;
  struct sockaddr_in6   padding;
  socklen_t             socklen;
  ngx_str_t             name;
  u_char                ipstr[NGX_SOCKADDR_STRLEN+1];

#if (NGX_HTTP_SSL)
  ngx_ssl_session_t    *ssl_session;   /* local to a process */
#endif
} ngx_http_upstream_jdomain_peer_t;

/**
 * The jdomain specific configuration for an upstream server.
 **/
/* TODO: Rename some of these members. */
typedef struct {
  /** The resolved upstreams which will be connected to. */
  ngx_http_upstream_jdomain_peer_t *peers;
  /** The default port to use when connecting to a peer. */
  ngx_uint_t                        default_port;
  /** The maximum number of peers to store for this server. */
  ngx_uint_t                        resolved_max_ips;
  /** The current number of resolved addresses for the hostname. */
  ngx_uint_t                        resolved_num;
  /** The hostname associated with this server which will be resolved. */
  ngx_str_t                         resolved_domain;
  /** The current state of DNS resolution (DONE or WAIT). */
  ngx_int_t                         resolved_status;
  /** The index of the address which will be next connected to. */
  ngx_uint_t                        resolved_index;
  /** The last time the hostname was resolved. */
  time_t                            resolved_access;
  /** How frequently the hostname should be re-resolved. */
  time_t                            resolved_interval;
  /** Whether connecting to an upstream should be retried. */
  /* TODO: Should this be a flag? */
  ngx_uint_t                        upstream_retry;
} ngx_http_upstream_jdomain_srv_conf_t;

/**
 * The data to be attached to a peer connection to be accessible
 * by the hooks on that connection.
 */
typedef struct {
  /** The jdomain config for this upstream peer. */
  ngx_http_upstream_jdomain_srv_conf_t *conf;
  /** The configuration for the containing location block. */
  ngx_http_core_loc_conf_t             *clcf;
  /** The index of the peer which is being connected to. */
  ngx_int_t                             current;
} ngx_http_upstream_jdomain_peer_data_t;

/**
 * @section Forward references.
 **/
#if (NGX_HTTP_SSL)
/* Why are these not static? */
  ngx_int_t ngx_http_upstream_set_jdomain_peer_session(ngx_peer_connection_t *pc, void *data);
  void ngx_http_upstream_save_jdomain_peer_session(ngx_peer_connection_t *pc, void *data);
#endif

static char *ngx_http_upstream_jdomain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void * ngx_http_upstream_jdomain_create_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_upstream_jdomain_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_jdomain_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_jdomain_get_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_jdomain_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);
static void ngx_http_upstream_jdomain_handler(ngx_resolver_ctx_t *ctx);

/**
 * The directives defined by this module.
 **/  
/* TODO: Document more heavily */
static ngx_command_t  ngx_http_upstream_jdomain_commands[] = {
  /** The 'jdomain' directive. */
  {                             
    ngx_string("jdomain"),            /**< Directive keyword.*/
    NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, /**< Supported location and arity.  */
    ngx_http_upstream_jdomain,        /**< Setup function. */
    0,                                /**< No offset, only support one context. */
    0,                                /**< No offset for storing configuration on struct. */
    NULL                              /**< ?? */
  },

  /* End of sequence sentinel. */
  ngx_null_command
};

/**
 * The module context which defines the configuration handlers.
 *
 * The handlers are in charge of processing the directives in light
 * of the assorted configuration locations in order to determine
 * the actual configuration for the module.
 **/
static ngx_http_module_t  ngx_http_upstream_jdomain_module_ctx = {
  NULL,                                           /**< Preconfiguration. */
  NULL,                                           /**< Postconfiguration. */

  NULL,                                           /**< Create main configuration. */
  NULL,                                           /**< Init main configuration. */

  ngx_http_upstream_jdomain_create_conf,          /**< Create server configuration. */
  NULL,                                           /**< Merge server configuration. */

  NULL,                                           /**< Create location configuration. */
  NULL                                            /**< Merge location configuration. */
};

/**
 * The module definition which provides the top level mapping of module hooks.
 **/
ngx_module_t  ngx_http_upstream_jdomain_module = {
  NGX_MODULE_V1,                                        /**< Macro for module version header. */
  &ngx_http_upstream_jdomain_module_ctx,                /**< Module context to be passed as arg. */
  ngx_http_upstream_jdomain_commands,                   /**< Module directives. */
  NGX_HTTP_MODULE,                                      /**< Module type. */

  /* Hooks into assorted nginx lifecycle events (many of which are not even supported). */
  NULL,                                                 /**< Init master. */
  NULL,                                                 /**< Init module. */
  NULL,                                                 /**< Init process. */
  NULL,                                                 /**< Init thread. */
  NULL,                                                 /**< Exit thread. */
  NULL,                                                 /**< Exit process. */
  NULL,                                                 /**< Exit master. */
  NGX_MODULE_V1_PADDING                                 /**< Macro for module version footer. */
};

/**
 * Hook to replace the standard upstream peer initialization.
 *
 * Overrides the peer init hook and updates the jdomain config
 * for the current upstream server to reflect a DONE resolution state.
 *
 * @param[in] cf The nginx configuration.
 * @param[in] us The upstream server configuration for the destination peer.
 * @returns nginx status (NGX_OK).
 */
static ngx_int_t
ngx_http_upstream_jdomain_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
  ngx_http_upstream_jdomain_srv_conf_t	*urcf;

  us->peer.init = ngx_http_upstream_jdomain_init_peer;

  urcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_jdomain_module);
  urcf->resolved_status = NGX_JDOMAIN_STATUS_DONE;

  return NGX_OK;
}

/**
 * Hook to replace the methods on the peer connection struct.
 *
 * Overrides the peer connection management to use the functionality from this module.
 *
 * @param[in] r The current request
 * @param[in] us The upstream server configuration for the destination peer.
 * @returns nginx status (ERROR on allocation issue, otherwise OK).
 */
static ngx_int_t
ngx_http_upstream_jdomain_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us) {
  ngx_http_upstream_jdomain_peer_data_t	*urpd;
  ngx_http_upstream_jdomain_srv_conf_t  *urcf;

  urcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_jdomain_module);

  /* Allocate peer and populate data. */
  urpd = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_jdomain_peer_data_t));
  if (urpd == NULL) {
    return NGX_ERROR;
  }
  urpd->conf = urcf;
  urpd->clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
  urpd->current = -1;
	
  /* Override the members of the ngx_peer_connection (ngx_event_connect.h) */
  r->upstream->peer.data = urpd;
  r->upstream->peer.free = ngx_http_upstream_jdomain_free_peer;
  r->upstream->peer.get = ngx_http_upstream_jdomain_get_peer;

  if (urcf->upstream_retry) {
    r->upstream->peer.tries = (urcf->resolved_num != 1) ? urcf->resolved_num : 2;
  } else {
    r->upstream->peer.tries = 1;
  }

#if (NGX_HTTP_SSL)
  r->upstream->peer.set_session = ngx_http_upstream_set_jdomain_peer_session;
  r->upstream->peer.save_session = ngx_http_upstream_save_jdomain_peer_session;
#endif

  return NGX_OK;
}

/**
 * Hook for getting a peer connection to perform DNS resolutions and use the jdomain structs.
 *
 * Oeverwrites standard hook.
 * This uses the data stashed by the previous hooks to determine whether
 * the target upstream server is due for a re-resolution and, if so,
 * attempts to initiate that resolution.
 * 
 * When configuring the connection, loads the required data from the (updated)j
 * domain config rather than the standard nginx upstream config.
 *
 * @param[in] pc The peer connection which is being established.
 * @param[in] data A void pointer where arguments to this function may be stashed.
 * @returns nginx status (NGX_OK)
 **/
static ngx_int_t
ngx_http_upstream_jdomain_get_peer(ngx_peer_connection_t *pc, void *data)
{
  ngx_http_upstream_jdomain_peer_data_t	*urpd;
  ngx_http_upstream_jdomain_srv_conf_t  *urcf;

  ngx_resolver_ctx_t                    *ctx;
  ngx_http_upstream_jdomain_peer_t      *peer;

  /* Type the void pointer and fetch some data out of it. */ 
  urpd = data;
  urcf = urpd->conf;

  pc->cached = 0;
  pc->connection = NULL;

  /* If already resolving, proceed. */
  if (urcf->resolved_status == NGX_JDOMAIN_STATUS_WAIT) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "upstream_jdomain: resolving"); 
    goto assign;
  }

  /* If least resolution was recent enough, proceed. */
  if (ngx_time() <= urcf->resolved_access + urcf->resolved_interval) {
    goto assign;
  }

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "upstream_jdomain: update from DNS cache"); 

  /* Time to attempt to re-resolve... */

  /* Allocate resolver context. */
  ctx = ngx_resolve_start(urpd->clcf->resolver, NULL);
  
  /* If resolver context can't be allocated, proceed and assume old value is good enough. */
  if (ctx == NULL) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "upstream_jdomain: resolve_start fail"); 
    goto assign;
  }
  if (ctx == NGX_NO_RESOLVER) {
    ngx_log_error(NGX_LOG_ALERT, pc->log, 0, "upstream_jdomain: no resolver"); 
    goto assign;
  }
  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "upstream_jdomain: resolve_start ok"); 

  /* Populate the context with the info for this upstram. */
  ctx->name = urcf->resolved_domain;
  ctx->handler = ngx_http_upstream_jdomain_handler;
  ctx->data = urcf;
  ctx->timeout = urpd->clcf->resolver_timeout;

  /* Mark the resolution in progress to avoid double submission. */
  urcf->resolved_status = NGX_JDOMAIN_STATUS_WAIT;
  
  /* Start resolution and log any issues. */
  if (ngx_resolve_name(ctx) != NGX_OK) {
    ngx_log_error(NGX_LOG_ALERT, pc->log, 0, "upstream_jdomain: resolve name \"%V\" fail", &ctx->name);
  }

assign:
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "upstream_jdomain: resolved_num=%ud", urcf->resolved_num); 

  /* Select the next peer up in the rotation. */
  if (urpd->current == -1) {
    urcf->resolved_index = (urcf->resolved_index + 1) % urcf->resolved_num;

    urpd->current = urcf->resolved_index;
  } else {
    urpd->current = (urpd->current + 1) % urcf->resolved_num;
  }
  peer = &(urcf->peers[urpd->current]);

  /* Load the peer's data into the connection struct. */
  pc->sockaddr = &peer->sockaddr;
  pc->socklen = peer->socklen;
  pc->name = &peer->name;

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                 "upstream_jdomain: upstream to DNS peer (%s:%ud)",
                 inet_ntoa(((struct sockaddr_in*)(pc->sockaddr))->sin_addr),
                 ntohs((unsigned short)((struct sockaddr_in*)(pc->sockaddr))->sin_port));

  return NGX_OK;
}

/**
 * Hook for when a peer connection is closed.
 *
 * Decrments any tries remaining for a connection.
 *
 * @param[in,out] pc The peer connection.
 * @param[in] data Data stashed no the connection.
 **/
static void
ngx_http_upstream_jdomain_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state)
{
  if (pc->tries > 0) {
    pc->tries--;
  }
}

/**
 * Handler for the 'jdomain' directive.
 *
 * @param[in] cf The nginx configuration.
 * @param[in] cmd The nginx command?
 * @param[in] conf Stashed config data.
 * @returns nginx configuration status.
 **/
static char *
ngx_http_upstream_jdomain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_upstream_srv_conf_t         *uscf;
  ngx_http_upstream_jdomain_srv_conf_t *urcf;
  ngx_http_upstream_server_t	       *us;

  /* Utility automatic variables */
  /* The values of the directive arguments. */
  ngx_str_t                            *value;
  /* Utility string reference to assist in parsing. */
  ngx_str_t                             s;
  /* Reused index. */
  ngx_uint_t                            i;

  /* The interval at which hostnames will be resolved. */
  time_t                                interval;
  /* The hostname argument for the directive. */
  ngx_str_t                             domain;
  /* The default port for an upstream server. */
  ngx_int_t                             default_port;
  /* The maximum number of ips to resolve for a given hostname. */
  ngx_int_t                             max_ips;
  /* Whether to retry connections. */
  /* TODO: should this just be a flag? */
  ngx_uint_t                            retry;
  ngx_http_upstream_jdomain_peer_t     *paddr;
  ngx_url_t                             u;

  /* Set some defaults. */
  interval = 1;
  default_port = 80;
  max_ips = 20;
  retry = 1;
  domain.data = NULL;
  domain.len = 0;

  /* Prep the standard upstream configuation. */

  /* Fetch the upstream configuration. */
  uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

  /* Make sure servers is not NULL. */
  if(uscf->servers == NULL) {
    uscf->servers = ngx_array_create(cf->pool, 1, sizeof(ngx_http_upstream_server_t));
    if(uscf->servers == NULL) {
      return NGX_CONF_ERROR;
    }
  }

  /* Allocate and zero out the upstream being created. */
  us = ngx_array_push(uscf->servers);
  if (us == NULL) {
    return NGX_CONF_ERROR;
  }
  ngx_memzero(us, sizeof(ngx_http_upstream_server_t));

  /* Add some jdomain specific goodness. */

  /* Fetch the jdomain configuration. */
  urcf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_jdomain_module);
  /* Override the hooks. */
  uscf->peer.init_upstream = ngx_http_upstream_jdomain_init;

  /* Parse the directive arguments. */
  value = cf->args->elts;

  domain.data = value[1].data;
  domain.len  = value[1].len;

  for (i=2; i < cf->args->nelts; i++) {

    if (ngx_strncmp(value[i].data, "port=", 5) == 0) {
      default_port = ngx_atoi(value[i].data+5, value[i].len - 5);
      if (default_port == NGX_ERROR || default_port < 1 || default_port > 65535) {
        goto invalid;
      }
      continue;
    }

    if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
      s.len = value[i].len - 9;
      s.data = &value[i].data[9];
      interval = ngx_parse_time(&s, 1);
      if (interval == (time_t) NGX_ERROR) {
        goto invalid;
      }
      continue;
    }

    if (ngx_strncmp(value[i].data, "max_ips=", 8) == 0) {
      max_ips = ngx_atoi(value[i].data + 8, value[i].len - 8);
      if (max_ips == NGX_ERROR || max_ips < 1) {
        goto invalid;
      }
      continue;
    }

    if (ngx_strncmp(value[i].data, "retry_off", 9) == 0) {
      retry = 0;
      continue;
    }

    goto invalid;
  }

  /* Populate jdomain configuration.  */

  /* Allocate peers. */
  urcf->peers = ngx_pcalloc(cf->pool, max_ips * sizeof(ngx_http_upstream_jdomain_peer_t));
  if (urcf->peers == NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_palloc peers fail");
    return NGX_CONF_ERROR;
  }

  urcf->resolved_interval = interval;
  urcf->resolved_domain = domain;
  urcf->default_port = default_port;
  urcf->resolved_max_ips = max_ips;
  urcf->upstream_retry = retry;

  /* Load and parse domain to do initial resolve. */
  ngx_memzero(&u, sizeof(ngx_url_t));
  u.url = domain;
  u.default_port = (in_port_t) urcf->default_port;
  if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
    if (u.err) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s in upstream \"%V\"", u.err, &u.url);
    }
    return NGX_CONF_ERROR;
  }

  /* Populate peers with resolved addresses. */
  urcf->resolved_num = 0;
  for (i=0; i<u.naddrs; i++) {
    paddr = &urcf->peers[urcf->resolved_num];
    paddr->sockaddr = *((struct sockaddr*) u.addrs[i].sockaddr);
    paddr->socklen = u.addrs[i].socklen; 
    paddr->name = u.addrs[i].name;

    urcf->resolved_num++;
    if (urcf->resolved_num >= urcf->resolved_max_ips) {
      break;
    }
  }

  /*urcf->resolved_index = 0;*/
  /* Initialize the last resolved rime */
  urcf->resolved_access = ngx_time();

  return NGX_CONF_OK;

  /* FIXME: Accessing i here smells horrible. Move to a function or macro. */
invalid:
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[i]);

  return NGX_CONF_ERROR;
}

/**
 * Create a jdomain configuration for the current server configuration.
 *
 * @param[in] cf The nginx configuration.
 * @returns The created ngx_http_upstream_jdomain_srv_conf.
 **/
static void *
ngx_http_upstream_jdomain_create_conf(ngx_conf_t *cf)
{
  ngx_http_upstream_jdomain_srv_conf_t	*conf;

  /* FIXME: Make this one line? */
  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_jdomain_srv_conf_t));

  if (conf == NULL) {
    return NULL;
  }

  return conf;
}

/**
 * The handler for completed DNS resolutions.
 *
 * @param[in] The resolver context for the current DNS query.
 */
static void
ngx_http_upstream_jdomain_handler(ngx_resolver_ctx_t *ctx)
{
  struct sockaddr                      *addr;
  ngx_uint_t                            i;
  ngx_resolver_t                       *r;
  ngx_http_upstream_jdomain_peer_t     *peer;
  ngx_http_upstream_jdomain_srv_conf_t *urcf;

  /* Unpack some data from the context argument. */
  r = ctx->resolver;
  urcf = (ngx_http_upstream_jdomain_srv_conf_t *) ctx->data;

  /* Some initial sanity checks. */
  ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
                 "upstream_jdomain: \"%V\" resolved state(%i: %s)",
                 &ctx->name, ctx->state,
                 ngx_resolver_strerror(ctx->state));

  if (ctx->state || ctx->naddrs == 0) {
    ngx_log_error(NGX_LOG_ERR, r->log, 0,
                  "upstream_jdomain: resolver failed ,\"%V\" (%i: %s))",
                  &ctx->name, ctx->state,
                  ngx_resolver_strerror(ctx->state));
    goto end;
  }

  urcf->resolved_num = 0;

  /* Update all returned addresses */
  /* TODO: This seems to gloss over possible partial coverage of existing data... */
  for (i=0; i < ctx->naddrs; i++) {

    peer = &urcf->peers[urcf->resolved_num];
    addr = &peer->sockaddr;

    /* Do the actual important bit of updating the address. */
    /* TODO: Too much referencing? */
    peer->socklen = ctx->addrs[i].socklen;
    ngx_memcpy(addr, ctx->addrs[i].sockaddr, peer->socklen);

    /* This seems potentially a little hamfisted */
    switch (addr->sa_family) {
    case AF_INET6:
      ((struct sockaddr_in6*) addr)->sin6_port = htons((u_short) urcf->default_port);
      break;
    default:
      ((struct sockaddr_in*) addr)->sin_port = htons((u_short) urcf->default_port);
    }

    /* TODO: hmm... */
    peer->name.data = peer->ipstr;
    peer->name.len = ngx_sock_ntop(addr, peer->socklen, peer->ipstr, NGX_SOCKADDR_STRLEN, 1);

    urcf->resolved_num++;

    if (urcf->resolved_num >= urcf->resolved_max_ips) {
      break;
    }
  }

  /* Finish up resolution and mark as completed. */
end:
  ngx_resolve_name_done(ctx);

  urcf->resolved_access = ngx_time();
  urcf->resolved_status = NGX_JDOMAIN_STATUS_DONE;
}

#if (NGX_HTTP_SSL)

/**
 * Hook to attaches an ssl_session to a connection.
 *
 * @param[in] pc The connection to which an SSL session should be attached.
 * @param[in] data The jdomain peer data stashed for this peer.
 * @returns ??
 **/
ngx_int_t
ngx_http_upstream_set_jdomain_peer_session(ngx_peer_connection_t *pc, void *data)
{
  ngx_http_upstream_jdomain_peer_data_t *urpd;

  ngx_int_t                              rc;
  ngx_ssl_session_t                     *ssl_session;
  ngx_http_upstream_jdomain_peer_t      *peer;

  /* Load some relevant data into locals. */
  urpd = data;
  peer = &urpd->conf->peers[urpd->current];
  ssl_session = peer->ssl_session;

  rc = ngx_ssl_set_session(pc->connection, ssl_session);

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                 "set session: %p:%d",
                 ssl_session, ssl_session ? ssl_session->references : 0);

  return rc;
}

/**
 * Hook to save the session for re-use.
 *
 * Fetches the session from the connection.
 * If a session is found, store it for the peer and free any previous session.
 *
 * @param[in] pc The current connection.
 * @param[in] data The jdomain peer data stashed for this peer.
 */
/* TODO: Is the new session guaranteed to not be equal to the old? */
void
ngx_http_upstream_save_jdomain_peer_session(ngx_peer_connection_t *pc, void *data)
{
  ngx_http_upstream_jdomain_peer_data_t  *urpd;
  ngx_ssl_session_t                      *old_ssl_session, *ssl_session;
  ngx_http_upstream_jdomain_peer_t       *peer;

  urpd = data;

  /* Fetch current session from connection. */
  ssl_session = ngx_ssl_get_session(pc->connection);
  if (ssl_session == NULL) {
    return;
  }

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
                 "save session: %p:%d", ssl_session, ssl_session->references);

  peer = &urpd->conf->peers[urpd->current];

  old_ssl_session = peer->ssl_session;
  peer->ssl_session = ssl_session;

  if (old_ssl_session) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "old session: %p:%d",
                   old_ssl_session, old_ssl_session->references);

    ngx_ssl_free_session(old_ssl_session);
  }
}

#endif
