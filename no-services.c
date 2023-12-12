
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

void setcfg(void);
void freecfg(void);
int noservices_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int noservices_configrun(ConfigFile *cf, ConfigEntry *ce, int type);

long CAP_ACCOUNTREGISTRATION = 0L;
long CAP_SASL_OVR = 0L;

char *construct_url(const char *base_url, const char *extra_params);
const char *accreg_capability_parameter(Client *client);
int accreg_capability_visible(Client *client);
void register_account(OutgoingWebRequest *request, OutgoingWebResponse *response);
void register_channel(OutgoingWebRequest *request, OutgoingWebResponse *response);
void ns_account_login(OutgoingWebRequest *request, OutgoingWebResponse *response);

// draft/account-registration= parameter MD
void regkeylist_free(ModData *m);
const char *regkeylist_serialize(ModData *m);
void regkeylist_unserialize(const char *str, ModData *m);


int sasl_capability_visible(Client *client);
const char *sasl_capability_parameter(Client *client);

CMD_FUNC(CMD_REGISTER);
CMD_FUNC(CMD_CREGISTER);
CMD_FUNC(CMD_LOGIN);
CMD_OVERRIDE_FUNC(CMD_AUTHENTICATE_OVR);


/* Config struct*/
struct cfgstruct {
	char *url;
	char *key;

	unsigned short int got_url;
	unsigned short int got_key;

	// account registration
	int register_before_connect;
	int register_custom_account;
	int register_email_required;

};

static struct cfgstruct cfg;

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
	"1.0", /* Version */
	"Services functionality but without services", /* Short description of module */
	"Valware",
	"unrealircd-6",
};

MOD_INIT()
{
	MARK_AS_GLOBAL_MODULE(modinfo);
	freecfg();
	setcfg();

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
	RegisterApiCallbackWebResponse(modinfo->handle, "register_account", register_account);
	RegisterApiCallbackWebResponse(modinfo->handle, "register_channel", register_channel);
	RegisterApiCallbackWebResponse(modinfo->handle, "ns_account_login", ns_account_login);
	CommandOverrideAdd(modinfo->handle, "AUTHENTICATE", 0, CMD_AUTHENTICATE_OVR);
	CommandAdd(modinfo->handle, "REGISTER", CMD_REGISTER, 3, CMD_USER | CMD_UNREGISTERED);
	CommandAdd(modinfo->handle, "CREGISTER", CMD_CREGISTER, 3, CMD_USER);
	CommandAdd(modinfo->handle, "LOGIN", CMD_LOGIN, 3, CMD_USER);

	ClientCapability *clicap = ClientCapabilityFindReal("sasl");
	ClientCapabilityDel(clicap);

	ClientCapabilityInfo cap;
	memset(&cap, 0, sizeof(cap));
	cap.name = "sasl";
	cap.visible = sasl_capability_visible;
	cap.parameter = sasl_capability_parameter;
	ClientCapabilityAdd(modinfo->handle, &cap, &CAP_SASL_OVR);

	moddata_client_set(&me, "saslmechlist", "PLAIN");

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
		unreal_log(ULOG_INFO, "accreg", "NOSERVICES_API_BAD_RESPONSE", NULL,
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
		unreal_log(ULOG_INFO, "accreg", "NOSERVICES_API_BAD_RESPONSE", NULL,
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
			sendto_server(client, 0, 0, NULL, ":%s SVSLOGIN %s %s %s",
				  me.name, "*", client->id, client->user->account);
			unreal_log(ULOG_INFO, "accreg", "ACCOUNT_REGISTRATION", NULL,
				   "New account: \"$account\" registered to $client",
				   log_data_string("account", client->user->account),
				   log_data_string("client", client->name ? client->name : "a pre-connected user"));
		}
		else if (!success && code && account)
		{
			sendto_one(client, NULL, "FAIL REGISTER %s %s :%s", code, account, reason);
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
CMD_FUNC(CMD_REGISTER)
{
	if (IsLoggedIn(client))
	{
		sendto_one(client, NULL, "FAIL REGISTER ALREADY_AUTHENTICATED %s :You are already authenticated to an account.", client->user->account);
		return;
	}
	if (BadPtr(parv[1]) || BadPtr(parv[2]) || BadPtr(parv[3]))
	{
		sendto_one(client, NULL, "FAIL REGISTER INVALID_PARAMS :Syntax: /REGISTER <account name> <email> <password>");
		return;
	}

	if (BadPtr(cfg.url) || BadPtr(cfg.key)) // no api set? no registration
	{
		sendto_one(client, NULL, "FAIL REGISTER TEMPORARILY_UNAVAILABLE %s :Registration has not been configured on this server.", parv[1]);
		return;
	}
	json_t *j;
	char *json_serialized;

	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("register")); // we would like to register plz
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client trying to register
	json_object_set_new(j, "account", json_string_unreal(parv[1])); // account name they wanna register (Can be "*")
	json_object_set_new(j, "email", json_string_unreal(parv[2])); // email they wanna use for registration (Can be "*")
	json_object_set_new(j, "password", json_string_unreal(parv[3])); // password

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
			sendto_one(client, NULL, "FAIL CREGISTER %s %s :%s", code, channel, reason);
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
CMD_FUNC(CMD_CREGISTER)
{
	Channel *chan;
	if (BadPtr(parv[1]))
	{
		sendto_one(client, NULL, "FAIL CREGISTER INVALID_PARAMS * :Syntax: /CREGISTER <channel name>");
		return;
	}
	if (!IsLoggedIn(client))
	{
		sendto_one(client, NULL, "FAIL CREGISTER NOT_LOGGED_IN %s :You must be logged into an account to register a channel.", parv[1]);
		return;
	}
	if (BadPtr(cfg.url) || BadPtr(cfg.key)) // no api set? no registration
	{
		sendto_one(client, NULL, "FAIL CREGISTER TEMPORARILY_UNAVAILABLE %s :Registration has not been configured on this server.", parv[1]);
		return;
	}

	chan = find_channel(parv[1]);
	if (!chan)
	{
		sendto_one(client, NULL, "FAIL CREGISTER INVALID_CHANNEL %s :Channel does not exist.", parv[1]);
		return;
	}
	if (has_channel_mode(chan, 'r'))
	{
		sendto_one(client, NULL, "FAIL CREGISTER ALREADY_REGISTERED %s :Channel is already registered.", parv[1]);
		return;
	}
	if (!IsMember(client, chan))
	{
		sendnumeric(client, ERR_NOTONCHANNEL, chan->name);
		return;
	}
	if (!check_channel_access(client, chan, "oaq"))
	{
		sendto_one(client, NULL, "FAIL CREGISTER NO_ACCESS %s :You may not register that channel.", parv[1]);
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
								config_warn("%s:%i: duplicate %s::%s directive, ignoring.", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
								errors++;
								continue;
							}
							cfg.register_custom_account = 1;
							continue;
						}

						if(!strcmp(cep3->name, "email-required"))
						{
							if(cfg.register_email_required) {
								config_warn("%s:%i: duplicate %s::%s directive, ignoring.", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
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
				config_warn("%s:%i: unknown item %s::%s::%s", cep2->file->filename, cep2->line_number, NO_SERVICES_CONF, cep->name, cep2->name); // Rep0t warn if unknown directive =]
			}
			continue;
		}
		// Anything else is unknown to us =]
		config_warn("%s:%i: unknown item %s::%s", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name); // So display just a warning
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
			}
		}
	}
	
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

	if (client) // if our client is still online and our channel still exists and they're in it
	{
		// yay they registered
		if (success)
		{
			strlcpy(client->user->account, account, sizeof(client->user->account));
			user_account_login(NULL, client);
			sendto_server(client, 0, 0, NULL, ":%s SVSLOGIN %s %s %s",
				  me.name, "*", client->id, client->user->account);
			unreal_log(ULOG_INFO, "login", "ACCOUNT_LOGIN_SUCCESS", NULL,
				   "$client successfully logged into account $account",
				   log_data_string("account", client->user->account),
				   log_data_string("client", client->name ? client->name : "A pre-connected user"));
			if (HasCapability(client, "sasl"))
				sendto_one(client, NULL, ":%s 903 %s :SASL authentication successful", me.name, account);
		}
		else if (!success && code && account)
		{
			
			unreal_log(ULOG_INFO, "login", "ACCOUNT_LOGIN_FAIL", NULL,
				   "$client failed to log into account $account",
				   log_data_string("account", account),
				   log_data_string("client", client->name ? client->name : "A pre-connected user"));
			if (HasCapability(client, "sasl"))
				sendto_one(client, NULL, ":%s 904 %s :%s", me.name, account, reason);
			else
				sendto_one(client, NULL, "FAIL LOGIN %s %s :%s", code, account, reason);
		}
	}

	json_decref(result);
}

/**
 * /LOGIN <password>
*/
CMD_FUNC(CMD_LOGIN)
{
	if (BadPtr(parv[1]))
	{
		sendto_one(client, NULL, "FAIL LOGIN INVALID_PARAMS * :Syntax: /LOGIN <password>");
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
	add_fake_lag(client, 5000); // lag 'em for 5 seconds
}

/** SASL */
CMD_OVERRIDE_FUNC(CMD_AUTHENTICATE_OVR)
{
	Client *agent_p = NULL;
	char *account = (char *)safe_alloc(50), *password = (char *)safe_alloc(400);
	/* Failing to use CAP REQ for sasl is a protocol violation. */
	if (BadPtr(parv[1]))
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
		sendto_one(client, NULL, "AUTHENTICATE +");
		return;
	}

	char buf[512];
	int n;
	n = b64_decode(parv[1], buf, sizeof(buf)-1);
	if (n <= 1)
		return;

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
		return;

	safe_strdup(account, segments[1]); // Assign the second segment to account
	safe_strdup(password, segments[2]); // Assign the third segment to password
	
	json_t *j;
	char *json_serialized;

	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("identify")); // we would like to register plz
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client trying to register
	json_object_set_new(j, "auth", json_string_unreal(account)); // name of the user
	json_object_set_new(j, "password", json_string_unreal(password)); // name of the channel they want to register

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
	add_fake_lag(client, 5000); // lag 'em for 5 seconds
	safe_free(account);
	safe_free(password);

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
	return moddata_client_get(&me, "saslmechlist"); /* NOTE: could still return NULL */
}
