/*
  Licence: GPLv3
  Copyright Ⓒ 2024 Valerie Pond
  */
#define NOSERVICES_VERSION "1.0.1.4"

/*** <<<MODULE MANAGER START>>>
module
{
		documentation "https://github.com/ValwareIRC/valware-unrealircd-mods/blob/main/no-services/README.md";
		troubleshooting "In case of problems, documentation or e-mail me at v.a.pond@outlook.com";
		min-unrealircd-version "6.1.3";
		max-unrealircd-version "6.*";
		post-install-text {
				"The module is installed. Now all you need to do is add a loadmodule line:";
				"loadmodule \"third/no-services\";";
				"And /REHASH the IRCd.";
				"The module does not need any other configuration.";
		}
}
*** <<<MODULE MANAGER END>>>
*/

#include "unrealircd.h"

#define NO_SERVICES_CONF "no-services"
#define REGCAP_NAME "draft/account-registration"
#define CERTFP_DEL 0
#define CERTFP_ADD 1
#define CERTFP_LIST 2
// Runs both when a fully-connected user authenticates or an authenticated user fully-connects lol
#define HOOKTYPE_NOSERV_CONNECT_AND_LOGIN 800

/** Called when a local user quits or otherwise disconnects (function prototype for HOOKTYPE_PRE_LOCAL_QUIT).
 * @param client		The client
 * @param result		 	A JSON object about the user
 *
 *	{
 *		"id": 29,
 *		"account_name": "bob",
 *		"first_name": null,
 *		"last_name": null,
 *		"password": "$argon2id$v=19$m=6144,t=2,p=2$P5bUJuJSarijl8abOiV1Lw$GIbxA06zp3Kk1pjWjcSc8E0MwgfBUAuO5MjfhYpksUI",
 *		"email": "bob@example.cn",
 *		"activated": null,
 *		"last_login": null,
 *		"registered_at": "2023-12-10 23:38:06",
 *		"roles": null,
 *		"meta": {
 *		"0": {
 *			"id": 11,
 *			"user_id": "bob",
 *			"meta_name": "ajoin",
 *			"meta_value": "#services"
 *		},
 *		"1": {
 *			"id": 12,
 *			"user_id": "bob",
 *			"meta_name": "ajoin",
 *			"meta_value": "#opers"
 *		}
 *	}
 *
 *	For an actual example, see `void do_ajoin(){...}`
 */
void hooktype_noserv_connect_and_login(Client *client, json_t *result);
// sasl stuff
#define SASL_TYPE_NONE 0
#define SASL_TYPE_PLAIN 1
#define SASL_TYPE_EXTERNAL 2
#define GetSaslType(x)			(moddata_client(x, sasl_md).i)
#define SetSaslType(x, y)		do { moddata_client(x, sasl_md).i = y; } while(0)
#define DelSaslType(x)		do { moddata_client(x, sasl_md).i = SASL_TYPE_NONE; } while(0)
ModDataInfo *sasl_md;


void setcfg(void);
void freecfg(void);
int noservices_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int noservices_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
void connect_query_user(Client *client);

long CAP_ACCOUNTREGISTRATION = 0L;
long CAP_SASL_OVR = 0L;

char *construct_url(const char *base_url, const char *extra_params);
const char *accreg_capability_parameter(Client *client);
int accreg_capability_visible(Client *client);
void register_account(OutgoingWebRequest *request, OutgoingWebResponse *response);
void register_channel(OutgoingWebRequest *request, OutgoingWebResponse *response);
void ns_account_login(OutgoingWebRequest *request, OutgoingWebResponse *response);
void ajoin_callback(OutgoingWebRequest *request, OutgoingWebResponse *response);
void connect_query_user_response(OutgoingWebRequest *request, OutgoingWebResponse *response);
void certfp_callback(OutgoingWebRequest *request, OutgoingWebResponse *response);

// draft/account-registration= parameter MD
void regkeylist_free(ModData *m);
const char *regkeylist_serialize(ModData *m);
void regkeylist_unserialize(const char *str, ModData *m);

// Who's SASLing how
void sat_free(ModData *m);
const char *sat_serialize(ModData *m);
void sat_unserialize(const char *str, ModData *m);

int noservices_hook_local_connect(Client *client);

void do_ajoin(Client *client, json_t *result);

int sasl_capability_visible(Client *client);
const char *sasl_capability_parameter(Client *client);

CMD_FUNC(cmd_register);
CMD_FUNC(cmd_cregister);
CMD_FUNC(cmd_login);
CMD_OVERRIDE_FUNC(cmd_authenticate_ovr);
CMD_FUNC(cmd_ajoin);
CMD_FUNC(cmd_logout);
CMD_FUNC(cmd_certfp);


/* Config struct*/
struct cfgstruct {
	char *url;
	char *key;

	unsigned short int got_url;
	unsigned short int got_key;
	unsigned short int got_password_strength_requirement;

	// account registration
	int register_before_connect;
	int register_custom_account;
	int register_email_required;
	int password_strength_requirement;

};

static struct cfgstruct cfg;

/** Test the validity of emails*/
int IsValidEmail(const char *email)
{
	if (!strstr(email,"@") || !strstr(email,"."))
		return 0;
	return 1;
}


int checkPasswordStrength(const char *password, int password_strength_requirement) {
	int length = strlen(password);
	int uppercase = 0, lowercase = 0, digits = 0, symbols = 0;
	
	for (int i = 0; i < length; i++) {
		if (isupper(password[i])) {
			uppercase = 1;
		} else if (islower(password[i])) {
			lowercase = 1;
		} else if (isdigit(password[i])) {
			digits = 1;
		} else {
			symbols = 1;
		}
	}
	
	int strength = uppercase + lowercase + digits + symbols;

	if (length >= 8 && strength >= password_strength_requirement) {
		return 1; // Password meets strength requirement
	} else {
		return 0; // Password does not meet strength requirement
	}
}


/** Query the No-Services API
 @param endpoint The endpoint of the API
 @param body The body to POST, typically JSON
 @param callback The callback function
*/
void query_api(const char *endpoint, char *body, const char *callback)
{
	OutgoingWebRequest *w = safe_alloc(sizeof(OutgoingWebRequest));
	json_t *j;
	NameValuePrioList *headers = NULL;
	add_nvplist(&headers, 0, "Content-Type", "application/json; charset=utf-8");
	add_nvplist(&headers, 0, "X-API-Key", cfg.key);
	/* Do the web request */
	char *our_url = construct_url(cfg.url, endpoint);
	safe_strdup(w->url, our_url);
	w->http_method = HTTP_METHOD_POST;
	w->body = body;
	w->headers = headers;
	w->max_redirects = 1;
	safe_strdup(w->apicallback, callback);
	url_start_async(w);
	free(our_url);
}

/** Query the No-Services API
 @param endpoint The endpoint of the API
 @param body The body to POST, typically JSON
 @param callback The callback function
*/
void send_email(const char *endpoint, char *body, const char *callback)
{
	OutgoingWebRequest *w = safe_alloc(sizeof(OutgoingWebRequest));
	json_t *j;
	NameValuePrioList *headers = NULL;
	add_nvplist(&headers, 0, "Content-Type", "application/json; charset=utf-8");
	add_nvplist(&headers, 0, "X-API-Key", cfg.key);
	/* Do the web request */
	char *our_url = construct_url(cfg.url, endpoint);
	safe_strdup(w->url, our_url);
	w->http_method = HTTP_METHOD_POST;
	w->body = body;
	w->headers = headers;
	w->max_redirects = 1;
	safe_strdup(w->apicallback, callback);
	url_start_async(w);
	free(our_url);
}

char *construct_url(const char *base_url, const char *extra_params) {
	size_t base_len = strlen(base_url);
	size_t params_len = strlen(extra_params);
	
	// Calculate the length of the resulting URL (+1 for the null terminator)
	size_t url_len = base_len + 1 + params_len;

	// Allocate memory for the URL
	char *url = (char *)safe_alloc(url_len);
	if (url != NULL) {
		// Copy the base URL into the constructed URL
		strncpy(url, base_url, base_len);
		url[base_len] = '\0'; // Null-terminate the base URL in the new string
		
		// Concatenate the extra parameters
		strncat(url, extra_params, params_len);
		url[url_len - 1] = '\0'; // Ensure null termination at the end
	}
	return url;
}


ModuleHeader MOD_HEADER
= {
	"third/no-services",	/* Name of module */
	NOSERVICES_VERSION, /* Version */
	"Services functionality but without services", /* Short description of module */
	"Valware",
	"unrealircd-6",
};

MOD_INIT()
{
	MARK_AS_GLOBAL_MODULE(modinfo);
	freecfg();
	setcfg();

	/** Account Registration cap key value
	 * eg "before-connect,email-required,custom-account-name"
	*/
	ModDataInfo mreq;
	memset(&mreq, 0, sizeof(mreq));
	mreq.name = "regkeylist";
	mreq.free = regkeylist_free;
	mreq.serialize = regkeylist_serialize;
	mreq.unserialize = regkeylist_unserialize;
	mreq.type = MODDATATYPE_CLIENT;
	if (!ModDataAdd(modinfo->handle, mreq))
	{
		config_error("Could not add ModData for regkeylist");
		return MOD_FAILED;
	}
	
	memset(&mreq, 0, sizeof(mreq));
	mreq.name = "sasl_auth_type";
	mreq.free = sat_free;
	mreq.serialize = sat_serialize;
	mreq.unserialize = sat_unserialize;
	mreq.type = MODDATATYPE_CLIENT;
	if (!(sasl_md = ModDataAdd(modinfo->handle, mreq)))
	{
		config_error("Could not add ModData for sasl_auth_type");
		return MOD_FAILED;
	}
	/** Account Registration cap `draft/account-registration`
	*/
	ClientCapabilityInfo accreg_cap; 
	memset(&accreg_cap, 0, sizeof(accreg_cap));
	accreg_cap.name = REGCAP_NAME;
	accreg_cap.visible = accreg_capability_visible;
	accreg_cap.parameter = accreg_capability_parameter;
	if (!ClientCapabilityAdd(modinfo->handle, &accreg_cap, &CAP_ACCOUNTREGISTRATION))
	{
		config_error("Could not add CAP for draft/account-registration. Please contact developer.");
		return MOD_FAILED;
	}
	
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, noservices_configrun);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_CONNECT, 9999, noservices_hook_local_connect); // we want to be called after auto-oper and such
	HookAddVoid(modinfo->handle, HOOKTYPE_NOSERV_CONNECT_AND_LOGIN, 0, do_ajoin); // custom hook baby
	RegisterApiCallbackWebResponse(modinfo->handle, "register_account", register_account);
	RegisterApiCallbackWebResponse(modinfo->handle, "register_channel", register_channel);
	RegisterApiCallbackWebResponse(modinfo->handle, "ns_account_login", ns_account_login);
	RegisterApiCallbackWebResponse(modinfo->handle, "ajoin_callback", ajoin_callback);
	RegisterApiCallbackWebResponse(modinfo->handle, "certfp_callback", certfp_callback);
	RegisterApiCallbackWebResponse(modinfo->handle, "connect_query_user_response", connect_query_user_response);
	CommandOverrideAdd(modinfo->handle, "AUTHENTICATE", 0, cmd_authenticate_ovr);
	CommandAdd(modinfo->handle, "REGISTER", cmd_register, 3, CMD_USER | CMD_UNREGISTERED);
	CommandAdd(modinfo->handle, "CREGISTER", cmd_cregister, 3, CMD_USER);
	CommandAdd(modinfo->handle, "LOGIN", cmd_login, 3, CMD_USER);
	CommandAdd(modinfo->handle, "LOGOUT", cmd_logout, MAXPARA, CMD_USER);
	CommandAdd(modinfo->handle, "AJOIN", cmd_ajoin, MAXPARA, CMD_USER);
	CommandAdd(modinfo->handle, "CERTFP", cmd_certfp, 2, CMD_USER);

	// Here, we take control of SASL but don't unload the original module because we
	// still wanna make use of the original event timer without duplicating code =]
	// so, remove the old ClientCapability for SASL
	ClientCapability *clicap = ClientCapabilityFindReal("sasl");
	ClientCapabilityDel(clicap);

	// and put our own version
	ClientCapabilityInfo cap;
	memset(&cap, 0, sizeof(cap));
	cap.name = "sasl";
	cap.visible = sasl_capability_visible;
	cap.parameter = sasl_capability_parameter;
	ClientCapabilityAdd(modinfo->handle, &cap, &CAP_SASL_OVR);

	return MOD_SUCCESS;
}

MOD_TEST()
{
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, noservices_configtest);
	return MOD_SUCCESS;
}
/* Is first run when server is 100% ready */
MOD_LOAD()
{
	return MOD_SUCCESS;
}

/* Called when module is unloaded */
MOD_UNLOAD()
{
	freecfg();
	return MOD_SUCCESS;
}

void freecfg(void)
{
	safe_free(cfg.url);
	safe_free(cfg.key);
	memset(&cfg, 0, sizeof(cfg));
}

void setcfg(void)
{
	safe_strdup(cfg.url, "");
	safe_strdup(cfg.key, "");
}

// callback for registering accounts
void register_account(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "register", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	// result->memory contains all the data of the web response, in our case
	// we assume it is a JSON response, so we are going to parse it.
	// If you were expecting BINARY data then you can still use result->memory
	// but then have a look at the length in result->memory_len.
	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "register", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}
	const char *key;
	json_t *value;
	char *reason = NULL;
	char *code = NULL;
	char *account = NULL;
	int success = 0;
	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "account"))
		{
			account = strdup(json_string_value(value));
		}
	}

	if (client) // if our client is still online
	{
		// yay they registered
		if (success && account)
		{
			strlcpy(client->user->account, account, sizeof(client->user->account));
			sendto_one(client, NULL, "REGISTER SUCCESS %s %s", account, reason);
			user_account_login(NULL, client);

			if (IsUser(client))
				RunHook(HOOKTYPE_NOSERV_CONNECT_AND_LOGIN, client, result);

			sendto_server(client, 0, 0, NULL, ":%s SVSLOGIN %s %s %s",
					me.name, "*", client->id, client->user->account);
			unreal_log(ULOG_INFO, "register", "ACCOUNT_REGISTRATION", NULL,
					"New account: \"$account\" registered to $client",
					log_data_string("account", client->user->account),
					log_data_string("client", client->name ? client->name : "a pre-connected user"));
		}
		else if (!success && code && account)
		{
			sendto_one(client, NULL, ":%s FAIL REGISTER %s %s :%s", me.name, code, account, reason);
		}
	}

	free(reason);
	free(code);
	free(account);
	json_decref(result);
}
/** Register accounts
 * /REGISTER <account name> <email> <password>
 */
CMD_FUNC(cmd_register)
{
	if (IsLoggedIn(client))
	{
		sendto_one(client, NULL, ":%s FAIL REGISTER ALREADY_AUTHENTICATED %s :You are already authenticated to an account.", me.name, client->user->account);
		return;
	}
	if (BadPtr(parv[1]) || BadPtr(parv[2]) || BadPtr(parv[3]))
	{
		sendto_one(client, NULL, ":%s FAIL REGISTER INVALID_PARAMS :Syntax: /REGISTER <account name> <email> <password>", me.name);
		return;
	}

	if (BadPtr(cfg.url) || BadPtr(cfg.key)) // no api set? no registration
	{
		sendto_one(client, NULL, ":%s FAIL REGISTER TEMPORARILY_UNAVAILABLE %s :Registration has not been configured on this server.", me.name, parv[1]);
		return;
	}

	if ((!IsUser(client) && MyConnect(client)) && !cfg.register_before_connect)
	{
		sendto_one(client, NULL, ":%s FAIL REGISTER COMPLETE_CONNECTION_REQUIRED %s :You must fully connect before registering an account.", me.name, parv[1]);
		return;
	}
	char account[NICKLEN + 2];
	
	strlcpy(account, (!strcmp(parv[1],"*")) ? client->name : parv[1], iConf.nick_length + 1);
	// Account name stuff
	// accounts follow nick standard
	if (!cfg.register_custom_account && strcmp(parv[1],"*") == -1 && strcmp(parv[1], client->name))
	{
		sendto_one(client, NULL, ":%s FAIL REGISTER ACCOUNT_NAME_MUST_BE_NICK %s :Your account name must be your nickname.", me.name, account);
		return;
	}
	if (!do_nick_name(account))
	{
		sendto_one(client, NULL, ":%s FAIL REGISTER BAD_ACCOUNT_NAME %s :Your account name must be a valid nickname.", me.name, account);
		return;
	}
	// Email stuff
	if (cfg.register_email_required // we need their email
		&& ((!strcmp(parv[2],"*")) // and they either didn't give it
		|| !IsValidEmail(parv[2]))) // or it was invalid
	{
		sendto_one(client, NULL, ":%s FAIL REGISTER INVALID_EMAIL %s :Your email address is invalid.", me.name, account);
		return;
	}

	if (!checkPasswordStrength(parv[3], cfg.password_strength_requirement))
	{
		sendto_one(client, NULL, ":%s FAIL REGISTER PASSWORD_TOO_WEAK %s :Your password is too weak. Please choose a stronger password", me.name, account);
		return;
	}

	const char *password_hash = NULL;
	
	if (!(password_hash = Auth_Hash(6, parv[3])))
	{
		sendto_one(client, NULL, ":%s FAIL REGISTER SERVER_BUG %s :The hashing mechanism was not supported. Please contact an administrator.", me.name, parv[1]);
		return;
	}
	json_t *j;
	char *json_serialized;

	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("register")); // we would like to register plz
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client trying to register
	json_object_set_new(j, "account", json_string_unreal(parv[1])); // account name they wanna register
	json_object_set_new(j, "email", json_string_unreal(parv[2])); // email they wanna use for registration (Can be "*")
	json_object_set_new(j, "password", json_string_unreal(password_hash)); // password

	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "registration", "BUG_SEREALIZE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}
	json_decref(j);

	query_api("account", json_serialized, "register_account");
	add_fake_lag(client, 5000); // lag 'em for 5 seconds
}

// the callback for registering channels
void register_channel(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	Channel *chan = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "chanreg", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	// result->memory contains all the data of the web response, in our case
	// we assume it is a JSON response, so we are going to parse it.
	// If you were expecting BINARY data then you can still use result->memory
	// but then have a look at the length in result->memory_len.
	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "chanreg", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}
	const char *key;
	json_t *value;
	char *reason = NULL;
	char *code = NULL;
	char *channel = NULL;
	int success = 0;
	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "channel"))
		{
			channel = strdup(json_string_value(value));
			chan = find_channel(channel);
		}
	}

	if (client && chan && IsMember(client, chan) && IsLoggedIn(client)) // if our client is still online and our channel still exists and they're in it
	{
		// yay they registered
		if (success)
		{
			char *modes;
			const char *mode_args[3];

			mode_args[0] = "rq";
			mode_args[1] = client->name;
			mode_args[2] = 0;

			do_mode(chan, &me, NULL, 3, mode_args, 0, 0);// make this ACTUALLY sent by the server for the mode_is_ok check
			sendto_one(client, NULL, "CREGISTER SUCCESS %s :Channel %s has been registered to your account", chan->name, client->user->account);
			unreal_log(ULOG_INFO, "chanreg", "CHANNEL_REGISTRATION", NULL,
					"New channel: \"$chan\" registered to account \"$account\"",
					log_data_string("chan", channel),
					log_data_string("account", client->user->account));
			
		}
		else if (!success && code && channel)
		{
			sendto_one(client, NULL, ":%s FAIL CREGISTER %s %s :%s", me.name, code, channel, reason);
		}
	}

	free(reason);
	free(code);
	free(channel);
	json_decref(result);
}

/** Register a channel
 * /CREGISTER <channel>
 */
CMD_FUNC(cmd_cregister)
{
	Channel *chan;
	if (BadPtr(parv[1]))
	{
		sendto_one(client, NULL, ":%s FAIL CREGISTER INVALID_PARAMS * :Syntax: /CREGISTER <channel name>", me.name);
		return;
	}
	if (!IsLoggedIn(client))
	{
		sendto_one(client, NULL, ":%s FAIL CREGISTER NOT_LOGGED_IN %s :You must be logged into an account to register a channel.", me.name, parv[1]);
		return;
	}
	if (BadPtr(cfg.url) || BadPtr(cfg.key)) // no api set? no registration
	{
		sendto_one(client, NULL, ":%s FAIL CREGISTER TEMPORARILY_UNAVAILABLE %s :Registration has not been configured on this server.", me.name, parv[1]);
		return;
	}

	chan = find_channel(parv[1]);
	if (!chan)
	{
		sendto_one(client, NULL, ":%s FAIL CREGISTER INVALID_CHANNEL %s :Channel does not exist.", me.name, parv[1]);
		return;
	}
	if (has_channel_mode(chan, 'r'))
	{
		sendto_one(client, NULL, ":%s FAIL CREGISTER ALREADY_REGISTERED %s :Channel is already registered.", me.name, parv[1]);
		return;
	}
	if (!IsMember(client, chan))
	{
		sendnumeric(client, ERR_NOTONCHANNEL, chan->name);
		return;
	}
	if (!check_channel_access(client, chan, "oaq"))
	{
		sendto_one(client, NULL, ":%s FAIL CREGISTER NO_ACCESS %s :You may not register that channel.", me.name, parv[1]);
		return;
	}

	json_t *j;
	char *json_serialized;

	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("register")); // we would like to register plz
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client trying to register
	json_object_set_new(j, "account", json_string_unreal(client->user->account)); // account of the user
	json_object_set_new(j, "channel", json_string_unreal(parv[1])); // name of the channel they want to register

	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "chanreg", "BUG_SEREALIZE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}
	json_decref(j);
	query_api("channel", json_serialized, "register_channel");
	add_fake_lag(client, 5000); // lag 'em for 5 seconds
}

int accreg_capability_visible(Client *client)
{
	return 1;
}

void regkeylist_free(ModData *m)
{
	safe_free(m->str);
}

const char *regkeylist_serialize(ModData *m)
{
	if (!m->str)
		return NULL;
	return m->str;
}

void regkeylist_unserialize(const char *str, ModData *m)
{
	safe_strdup(m->str, str);
}

const char *sat_serialize(ModData *m)
{
	static char buf[32];
	if (m->i == 0)
		return NULL; /* not set */
	snprintf(buf, sizeof(buf), "%d", m->i);
	return buf;
}
void sat_free(ModData *m)
{
    m->i = 0;
}
void sat_unserialize(const char *str, ModData *m)
{
    m->i = atoi(str);
}
const char *accreg_capability_parameter(Client *client)
{
	return moddata_client_get(&me, "regkeylist");
}


int noservices_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	int errors = 0; // Error count
	int i; // Iterat0r
	ConfigEntry *cep, *cep2, *cep3; // To store the current variable/value pair etc, nested

	// Since we'll add a top-level block to unrealircd.conf, need to filter on CONFIG_MAIN lmao
	if(type != CONFIG_MAIN)
		return 0; // Returning 0 means idgaf bout dis

	// Check for valid config entries first
	if(!ce || !ce->name)
		return 0;

	// If it isn't our block, idc
	if(strcmp(ce->name, NO_SERVICES_CONF))
		return 0;

	// Loop dat shyte
	for(cep = ce->items; cep; cep = cep->next)
	{
		// Do we even have a valid name l0l?
		// This should already be checked by Unreal's core functions but there's no harm in having it here too =]
		if(!cep->name)
		{
			config_error("%s:%i: blank %s item", cep->file->filename, cep->line_number, NO_SERVICES_CONF); // Rep0t error
			errors++; // Increment err0r count
			continue; // Next iteration imo tbh
		}

		if(!strcmp(cep->name, "api-url"))
		{
			if(cfg.got_url)
			{
				config_error("%s:%i: duplicate %s::%s directive. Only one URL is supported at this time.", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
				errors++;
				continue;
			}

			cfg.got_url = 1;
			if(!strlen(cep->value))
			{
				config_error("%s:%i: %s::%s must be non-empty", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
				errors++;
			}

			continue;
		}

		if(!strcmp(cep->name, "api-key"))
		{
			if(cfg.got_key)
			{
				config_error("%s:%i: duplicate %s::%s directive", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
				errors++;
				continue;
			}

			cfg.got_key = 1;
			if(!strlen(cep->value))
			{
				config_error("%s:%i: %s::%s must be non-empty", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
				errors++;
			}
			continue;
		}
		
		if(!strcmp(cep->name, "account-registration"))
		{
			for(cep2 = cep->items; cep2; cep2 = cep2->next)
			{
				if(!cep2->name)
				{
					config_error("%s:%i: blank %s::%s entry", cep2->file->filename, cep2->line_number, NO_SERVICES_CONF, cep->name); // Rep0t error
					errors++;
					continue;
				}

				if(!strcmp(cep2->name, "options"))
				{
					for (cep3 = cep2->items; cep3; cep3 = cep3->next)
					{
						if(!strcmp(cep3->name, "before-connect"))
						{
							if(cfg.register_before_connect) {
								config_warn("%s:%i: duplicate %s::%s directive, ignoring.", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
								errors++;
								continue;
							}
							cfg.register_before_connect = 1;
							continue;
						}
						
						if(!strcmp(cep3->name, "custom-account-name"))
						{
							if(cfg.register_custom_account) {
								config_warn("%s:%i: duplicate %s::%s directive, ignoring.", cep3->file->filename, cep3->line_number, NO_SERVICES_CONF, cep3->name);
								errors++;
								continue;
							}
							cfg.register_custom_account = 1;
							continue;
						}

						if(!strcmp(cep3->name, "email-required"))
						{
							if(cfg.register_email_required) {
								config_warn("%s:%i: duplicate %s::%s directive, ignoring.", cep3->file->filename, cep3->line_number, NO_SERVICES_CONF, cep3->name);
								errors++;
								continue;
							}
							cfg.register_email_required = 1;
							continue;
						}
						config_warn("%s:%i: unknown item %s::%s::%s::%s", cep3->file->filename, cep3->line_number, NO_SERVICES_CONF, cep->name, cep2->name, cep3->name); 
					}
					continue;
				}
				else if (!strcmp(cep2->name, "password-strength"))
				{
					if(cfg.got_password_strength_requirement) {
						config_warn("%s:%i: duplicate %s::%s directive, ignoring.", cep2->file->filename, cep2->line_number, NO_SERVICES_CONF, cep2->name);
						errors++;
						continue;
					}
					cfg.got_password_strength_requirement = 1;
					continue;
				}
				config_warn("%s:%i: unknown item %s::%s::%s", cep2->file->filename, cep2->line_number, NO_SERVICES_CONF, cep->name, cep2->name); // Rep0t warn if unknown directive =]
			}
			continue;
		}
		// Anything else is unknown to us =]
		config_warn("%s:%i: unknown item %s::%s", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name); // So display just a warning
	}
	if (!cfg.got_key || !cfg.got_url)
	{
		config_error("[no-services] You have not set your no-services block correctly.");
		errors++;
	}
	if (!cfg.got_password_strength_requirement)
	{
		config_warn("[no-services::account-registration::password-strength] You have not set a minimum password strength requirement. Defaulting to strongest possible strength.");
	}
	*errs = errors;
	return errors ? -1 : 1; // Returning 1 means "all good", -1 means we shat our panties
}


// "Run" the config (everything should be valid at this point)
int noservices_configrun(ConfigFile *cf, ConfigEntry *ce, int type) {
	ConfigEntry *cep, *cep2, *cep3; // To store the current variable/value pair etc, nested

	// Since we'll add a top-level block to unrealircd.conf, need to filter on CONFIG_MAIN lmao
	if(type != CONFIG_MAIN)
		return 0; // Returning 0 means idgaf bout dis

	// Check for valid config entries first
	if(!ce || !ce->name)
		return 0;

	// If it isn't noservices, idc
	if(strcmp(ce->name, NO_SERVICES_CONF))
		return 0;

	// Loop dat shyte
	for(cep = ce->items; cep; cep = cep->next) {
		// Do we even have a valid name l0l?
		if(!cep->name)
			continue; // Next iteration imo tbh

		if(!strcmp(cep->name, "api-url")) {
			safe_strdup(cfg.url, cep->value);
			continue;
		}

		if(!strcmp(cep->name, "api-key")) {
			safe_strdup(cfg.key, cep->value);
			continue;
		}
		if(!strcmp(cep->name, "account-registration"))
		{
			for(cep2 = cep->items; cep2; cep2 = cep2->next)
			{
				if(!cep2->name)
					continue;

				if(!strcmp(cep2->name, "options"))
				{
					for (cep3 = cep2->items; cep3; cep3 = cep3->next)
					{
						if(!strcmp(cep3->name, "before-connect"))
						{
							cfg.register_before_connect = 1;
							continue;
						}
						
						if(!strcmp(cep3->name, "custom-account-name"))
						{
							cfg.register_custom_account = 1;
							continue;
						}

						if(!strcmp(cep3->name, "email-required"))
						{
							cfg.register_email_required = 1;
							continue;
						}
					}
				}
				else if (!strcmp(cep2->name, "password-strength"))
				{
					cfg.got_password_strength_requirement = 1;
					cfg.password_strength_requirement = atoi(cep2->value);
					continue;
				}
			}
		}
	}
	if (!cfg.got_password_strength_requirement) // you have to explicitly enable 0 to work
		cfg.password_strength_requirement = 4;

	char *concatenated = (char *)safe_alloc(50);
	strcpy(concatenated, "");

	if (cfg.register_before_connect)
	{
			strcat(concatenated, "before-connect,");
	}
	if (cfg.register_custom_account)
		strcat(concatenated, "custom-account-name,");
	
	if (cfg.register_email_required)
		strcat(concatenated, "email-required");

	int len = strlen(concatenated);
	if (len > 0 && concatenated[len - 1] == ',') {
		concatenated[len - 1] = '\0';
	}
	moddata_client_set(&me, "regkeylist", concatenated);
	safe_free(concatenated);
	return 1; // We good
}

/* This is the callback function for logging in */
void ns_account_login(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "chanreg", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	// result->memory contains all the data of the web response, in our case
	// we assume it is a JSON response, so we are going to parse it.
	// If you were expecting BINARY data then you can still use result->memory
	// but then have a look at the length in result->memory_len.
	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "chanreg", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}
	const char *key;
	json_t *value;
	char *reason = NULL;
	char *code = NULL;
	char *account = NULL;
	int success = 0;
	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "account"))
		{
			account = strdup(json_string_value(value));
		}
	}

	if (client) // if our client is still online
	{
		// yay they registered
		if (success)
		{
			strlcpy(client->user->account, account, sizeof(client->user->account));
			user_account_login(NULL, client);
			sendto_server(client, 0, 0, NULL, ":%s SVSLOGIN %s %s %s",
					me.name, "*", client->id, client->user->account);
			if (IsUser(client))
				RunHook(HOOKTYPE_NOSERV_CONNECT_AND_LOGIN, client, result);
			unreal_log(ULOG_INFO, "login", "ACCOUNT_LOGIN_SUCCESS", NULL,
					"$client successfully logged into account $account",
					log_data_string("account", client->user->account),
					log_data_string("client", !BadPtr(client->name) ? client->name : "A pre-connected user"));
			if (HasCapability(client, "sasl"))
				sendto_one(client, NULL, ":%s 903 %s :SASL authentication successful", me.name, account);

		}
		else if (!success && code && account)
		{
			unreal_log(ULOG_INFO, "login", "ACCOUNT_LOGIN_FAIL", NULL,
					"$client failed to log into account $account",
					log_data_string("account", account),
					log_data_string("client", client->name ? client->name : client->id));
			if (HasCapability(client, "sasl"))
				sendto_one(client, NULL, ":%s 904 %s :%s", me.name, account, reason);
			else
				sendto_one(client, NULL, ":%s FAIL LOGIN %s %s :%s", me.name, code, account, reason);
			add_fake_lag(client, 10000); // ten second penalty for bad logins
		}
	}

	json_decref(result);
}

/**
 * /LOGIN <password>
*/
CMD_FUNC(cmd_login)
{
	if (BadPtr(parv[1]))
	{
		sendto_one(client, NULL, ":%s FAIL LOGIN INVALID_PARAMS * :Syntax: /LOGIN <password>", me.name);
		return;
	}
	json_t *j;
	char *json_serialized;

	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("identify")); // we would like to register plz
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client trying to register
	json_object_set_new(j, "auth", json_string_unreal(client->name)); // name of the user
	json_object_set_new(j, "password", json_string_unreal(parv[1])); // name of the channel they want to register

	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "login", "BUG_SEREALIZE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}
	json_decref(j);
	query_api("account", json_serialized, "ns_account_login");
	add_fake_lag(client, 2000);
}

/** SASL */
CMD_OVERRIDE_FUNC(cmd_authenticate_ovr)
{
	Client *agent_p = NULL;
	json_t *j;
	char *json_serialized;

	/* Failing to use CAP REQ for sasl is a protocol violation. */
	if (!HasCapability(client, "sasl") || BadPtr(parv[1]))
		return;

	if ((parv[1][0] == ':') || strchr(parv[1], ' '))
	{
		sendnumeric(client, ERR_CANNOTDOCOMMAND, "AUTHENTICATE", "Invalid parameter");
		return;
	}

	if (strlen(parv[1]) > 400)
	{
		sendnumeric(client, ERR_SASLTOOLONG);
		return;
	}

	if (client->user == NULL)
		make_user(client);

	if (!strcasecmp(parv[1], "PLAIN"))
	{
		SetSaslType(client, SASL_TYPE_PLAIN);
		sendto_one(client, NULL, ":%s AUTHENTICATE +", me.name);
		return;
	}
	else if (!strcasecmp(parv[1], "EXTERNAL"))
		SetSaslType(client, SASL_TYPE_EXTERNAL);

	if (!GetSaslType(client) || GetSaslType(client) == SASL_TYPE_NONE)
		return;

	else if (GetSaslType(client) == SASL_TYPE_PLAIN)
	{
		j = json_object();
		char *account = (char *)safe_alloc(50), *password = (char *)safe_alloc(400);
		char buf[512];
		int n;
		n = b64_decode(parv[1], buf, sizeof(buf)-1);
		if (n <= 1)
		{
			json_decref(j);
			return;
		}
		char *segments[3] = { NULL }; // Array to store segments
		int segmentIndex = 0;

		char *ptr = buf;
		segments[segmentIndex++] = ptr;

		while (segmentIndex < 3) {
			ptr++;
			if (*ptr == '\0') {
				segments[segmentIndex++] = ptr + 1;
			}
		}
		if (segmentIndex != 3)
		{
			json_decref(j);
			return;
		}
		safe_strdup(account, segments[1]); // Assign the second segment to account
		safe_strdup(password, segments[2]); // Assign the third segment to password

		j = json_object();
		json_object_set_new(j, "method", json_string_unreal("identify")); // we would like to register plz
		json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client trying to register
		json_object_set_new(j, "auth", json_string_unreal(account)); // name of the user
		json_object_set_new(j, "password", json_string_unreal(password)); // name of the user

		json_serialized = json_dumps(j, JSON_COMPACT);
		if (!json_serialized)
		{
			unreal_log(ULOG_WARNING, "login", "BUG_SEREALIZE", client,
					"Unable to serialize JSON request. Weird.");
			json_decref(j);
			return;
		}
		json_decref(j);
		query_api("account", json_serialized, "ns_account_login");
		safe_free(account);
		safe_free(password);
	}
	else if (GetSaslType(client) == SASL_TYPE_EXTERNAL)
	{
		j = json_object();
		ModDataInfo *moddata;
		moddata = findmoddata_byname("certfp", MODDATATYPE_CLIENT);
		if (!moddata || !moddata_client(client, moddata).str)
		{
			json_decref(j);
			sendto_one(client, NULL, ":%s FAIL CERTFP NO_CERT :You don't have a Certificate Fingerprint to add.", me.name);
			return;
		}
		json_object_set_new(j, "method", json_string_unreal("identify cert")); // we would like to register plz
		json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client trying to register
		json_object_set_new(j, "cert", json_string_unreal(moddata_client(client, moddata).str)); // cert to lookup

		json_serialized = json_dumps(j, JSON_COMPACT);
		if (!json_serialized)
		{
			unreal_log(ULOG_WARNING, "login", "BUG_SEREALIZE", client,
					"Unable to serialize JSON request. Weird.");
			json_decref(j);
			return;
		}
		json_decref(j);
		query_api("account", json_serialized, "ns_account_login");
	}
	DelSaslType(client);
}

int sasl_capability_visible(Client *client)
{
	/* Don't advertise 'sasl' capability if we are going to reject the
	 * user anyway due to set::plaintext-policy. This way the client
	 * won't attempt SASL authentication and thus it prevents the client
	 * from sending the password unencrypted (in case of method PLAIN).
	 */
	if (client && !IsSecure(client) && !IsLocalhost(client) && (iConf.plaintext_policy_user == POLICY_DENY))
		return 0;

	/* Similarly, don't advertise when we are going to reject the user
	 * due to set::outdated-tls-policy.
	 */
	if (IsSecure(client) && (iConf.outdated_tls_policy_user == POLICY_DENY) && outdated_tls_client(client))
		return 0;

	return 1;
}


const char *sasl_capability_parameter(Client *client)
{
	return "PLAIN,EXTERNAL"; /* NOTE: could still return NULL */
}

void ajoin_callback(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;

	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "ajoin", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "ajoin", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}

	const char *key;
	json_t *value;
	char *reason = NULL;
	char *code = NULL;
	char *channel = NULL;
	int success = 0;
	char *type = NULL;
	int add = 0;
	int list = 0;
	char *channels_list = "\0";

	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "channel"))
		{
			channel = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "autojoin"))
		{
			const char *key2;
			json_t *value2;
			int i = 0;

			json_object_foreach(value, key2, value2)
			{
				sendto_one(client, NULL, ":%s NOTE AJOIN LIST :%s", me.name, json_string_value(value2));
			}
			sendto_one(client, NULL, ":%s NOTE AJOIN END_OF_LIST :End of autojoin list.", me.name);
		}
		else if (!strcasecmp(key, "type"))
		{
			type = strdup(json_string_value(value));
			if (!strcmp(type,"add"))
				add++;
			else if (!strcmp(type,"list"))
				list++;
		}
	}

	if (success && channel)
	{
		sendto_one(client, NULL, ":%s AJOIN %s SUCCESS %s :You have successfully %s %s %s your auto-join list.", me.name, (add) ? "ADD" : "DEL", channel, (add) ? "added" : "deleted", channel, (add) ? "to" : "from");
	}
	else if (channel && reason && code)
	{
		sendto_one(client, NULL, ":%s FAIL AJOIN %s :Could not %s %s your auto-join list: %s", me.name, channel, (add) ? "add" : "delete", (add) ? "to" : "from", reason);
	}
	
	json_decref(result);
}

CMD_FUNC(cmd_ajoin)
{
	if (!IsLoggedIn(client))
	{
		sendto_one(client, NULL, ":%s FAIL AJOIN NOT_LOGGED_IN :You must be logged into an account to manage it.", me.name);
		return;
	}
	Channel *chan;
	// we already checked they're logged in
	if (BadPtr(parv[1]))
		return;

	json_t *j;
	char *json_serialized;
	j = json_object();

	if (!strcasecmp(parv[1],"add") && !BadPtr(parv[2]))
	{
		chan = find_channel(parv[2]);
		if (!chan || !IsMember(client, chan))
		{
			sendto_one(client, NULL, ":%s FAIL AJOIN NOT_ON_CHANNEL %s :You cannot add channels which you are not on to your auto-join list.", me.name, parv[2]);
			return;
		}
		json_object_set_new(j, "method", json_string_unreal("ajoin add")); // add the channel
	}

	else if (!strcasecmp(parv[1],"del") && !BadPtr(parv[2])) // we don't care if it exists or not
		json_object_set_new(j, "method", json_string_unreal("ajoin del")); // delete the channel
	else if (!strcasecmp(parv[1],"list"))
		json_object_set_new(j, "method", json_string_unreal("ajoin list")); // list the channels lmao
	
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client
	json_object_set_new(j, "account", json_string_unreal(client->user->account)); // ID of the client
	if (!BadPtr(parv[2]))
		json_object_set_new(j, "channel", json_string_unreal(parv[2])); // name of the user

	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "login", "BUG_SEREALIZE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}
	json_decref(j);
	query_api("account", json_serialized, "ajoin_callback");
	add_fake_lag(client, 1000); // lag 'em for 5 seconds
}


CMD_FUNC(cmd_logout)
{
	if (!IsLoggedIn(client))
	{
		sendto_one(client, NULL, ":%s FAIL LOGOUT NOT_LOGGED_IN :You must be logged into an account to log out.", me.name);
		return;
	}
	strlcpy(client->user->account, "0", sizeof(client->user->account));
	if (client->umodes & UMODE_REGNICK)
	{
		if (MyUser(client))
			sendto_one(client, NULL, ":%s MODE %s :-r", client->name, client->name);
		client->umodes &= ~UMODE_REGNICK;
	}
	user_account_login(recv_mtags, client);
	sendto_server(client, 0, 0, NULL, ":%s SVSLOGIN * %s 0", me.id, client->name);
}


int noservices_hook_local_connect(Client *client)
{
	if (!IsLoggedIn(client))
		return 0;
	connect_query_user(client);
	return 0;
}

void connect_query_user(Client *client)
{
	json_t *j;
	char *json_serialized;
	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("find"));
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client
	json_object_set_new(j, "account", json_string_unreal(client->user->account)); // ID of the client
	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "noserviceslocalcon", "BUG_SEREALIZE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}

	json_decref(j);
	query_api("account", json_serialized, "connect_query_user_response");
	add_fake_lag(client, 1000);
	return;
}


void connect_query_user_response(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "no-services-connect", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "no-services-connect", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}

	RunHook(HOOKTYPE_NOSERV_CONNECT_AND_LOGIN, client, result);
	
	json_decref(result);
}

// Search 
void do_ajoin(Client *client, json_t *result)
{
	const char *key;
	json_t *value;
	char *reason = NULL;
	char *code = NULL;
	char *account = NULL;
	int success = 0;
	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "user"))
		{
			const char *key2;
			json_t *value2;
			json_object_foreach(value, key2, value2)
			{
				if (!strcasecmp(key2, "meta"))
				{
					const char *key3;
					json_t *value3;
					json_object_foreach(value2, key3, value3)
					{
						const char *key4;
						json_t *value4;
						int is_ajoin = 0;
						json_object_foreach(value3, key4, value4)
						{
							if (!strcasecmp(key4, "meta_name") && !strcasecmp(json_string_value(value4),"ajoin"))
							{
								is_ajoin++;
								continue;
							}
							if (!strcasecmp(key4,"meta_value") && is_ajoin)
							{
								const char *parv[3];
								parv[0] = client->name;
								parv[1] = json_string_value(value4);
								parv[2] = NULL;
								do_cmd(client, NULL, "JOIN", 2, parv);
								is_ajoin = 0;
							}
							continue;
						}
						continue;
					}
					continue;
				}
				continue;
			}
			continue;
		}
	}
}

int certfp_helper(Client *client, int type, const char *param)
{
	json_t *j;
	char *json_serialized;
	j = json_object();
	if (type == CERTFP_ADD)
		json_object_set_new(j, "method", json_string_unreal("certfp add"));
	else if (type == CERTFP_DEL)
		json_object_set_new(j, "method", json_string_unreal("certfp del"));
	else if (type == CERTFP_LIST)
		json_object_set_new(j, "method", json_string_unreal("certfp list"));
	if (param)
		json_object_set_new(j, "cert", json_string_unreal(param));
	
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client
	json_object_set_new(j, "account", json_string_unreal(client->user->account)); // ID of the client
	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "noserviceslocalcon", "BUG_SEREALIZE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return 0;
	}

	json_decref(j);
	query_api("account", json_serialized, "certfp_callback");
	add_fake_lag(client, 500); // lag 'em for 5 seconds
	return 1;
}
/** CertFP command
 * View or manage your saved Certificate Fingerprint list
 */
CMD_FUNC(cmd_certfp)
{
	if (!IsLoggedIn(client))
		sendnumeric(client, ERR_NEEDREGGEDNICK, "CERTFP");
		
	else if (!strcasecmp(parv[1],"add"))
	{
		ModDataInfo *moddata;
		moddata = findmoddata_byname("certfp", MODDATATYPE_CLIENT);
		if (!moddata || !moddata_client(client, moddata).str)
		{
			sendto_one(client, NULL, ":%s FAIL CERTFP NO_CERT :You don't have a Certificate Fingerprint to add.", me.name);
			return;
		}
		certfp_helper(client, CERTFP_ADD, moddata_client(client, moddata).str);
		return;
	}
	else if (!strcasecmp(parv[1],"list"))
		certfp_helper(client, CERTFP_LIST, NULL);
	
	else if (!strcasecmp(parv[1],"del"))
	{
		if (!parv[2])
		{
			sendto_one(client, NULL, ":%s FAIL CERTFP INVALID_PARAM :You did not specify a fingerprint to delete.", me.name);
			return;
		}
		certfp_helper(client, CERTFP_DEL, parv[2]);
	}
	add_fake_lag(client, 500);
}


void certfp_callback(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "no-services-connect", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "no-services-connect", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}

	const char *key;
	json_t *value;
	char *type = NULL;
	char *reason = NULL;
	char *code = NULL;
	char *cert = NULL;
	int success = 0;
	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		if (!strcasecmp(key, "type"))
		{
			type = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "cert"))
		{
			cert = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "list"))
		{
			const char *key2;
			json_t *value2;
			json_object_foreach(value, key2, value2)
			{
				sendto_one(client, NULL, ":%s NOTE CERTFP LIST :%s", me.name, json_string_value(value2));
			}
			sendto_one(client, NULL, ":%s NOTE CERTFP END_OF_LIST :End of CertFP list", me.name);
		}
	}
	if (client && success && cert)
		sendto_one(client, NULL, ":%s NOTE CERTFP UPDATE_SUCCESSFUL %s :You have successfully updated your Certificate Fingerprint list.", me.name, cert);

	else if (client && !success && code && reason)
		sendto_one(client, NULL, ":%s FAIL CERTFP %s %s :%s", me.name, code, cert, reason);
	
	json_decref(result);
}
